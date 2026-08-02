"""`unauthenticated-method` filter for aws.rest-resource.

WHY THIS NEEDS CODE
-------------------
The declarative version of this control is wrong in BOTH directions, and the
reason is subtle enough that it survived review:

    filters:
      - type: rest-method
        key: authorizationType
        value: NONE
      - type: rest-method
        key: apiKeyRequired
        value: false
      - not:
          - type: rest-method
            key: httpMethod
            value: OPTIONS

`rest-method` returns the REST RESOURCE (the path) when ANY of its methods
matches -- see c7n/resources/apigw.py, FilterRestMethod.process, which does
`results.add(m['resourceId'])`. So the three filters combine at the path level,
not at the method level.

  FALSE POSITIVE. A path whose GET is authorizationType NONE but apiKeyRequired
  true, and whose POST is AWS_IAM but apiKeyRequired false, satisfies both
  filters and is reported -- although no single method is open.

  FALSE NEGATIVE. The `not:` reads "this path has no OPTIONS method at all",
  not "ignore the OPTIONS method". Any path with CORS preflight is silently
  dropped, including one with a genuinely unauthenticated GET.

Whether either error actually fires depends on the shape of the API: a path
carrying a single method cannot make the two `rest-method` filters land on
different ones, and an API without CORS has no OPTIONS method for the `not:`
to swallow. The structure is wrong either way, and both errors show up the
moment an API has several methods per path or a CORS preflight -- which is the
normal shape of a REST API.

WHAT IT DOES
------------
Evaluates each method on its own: open when authorizationType is NONE AND
apiKeyRequired is false AND the verb is not ignored.

It reads the DEPLOYED configuration, not the live one. `get_resources` returns
what the console shows, which includes methods created or edited after the last
deployment -- those are not callable yet, so reporting them is a false positive.
`get_deployment(embed=['apisummary'])` returns what each stage actually serves,
keyed by path, and a method counts as open if ANY stage serves it that way.

It also drops what cannot be reached at all:

  - APIs whose endpoint configuration is PRIVATE (only via a VPC endpoint)
  - APIs not deployed to any stage -- there is no URL to call

Matches are annotated with `c7n:UnauthenticatedMethods` listing the verbs, so
the finding names the method instead of just the path.

LIMITATION, STATED PLAINLY
--------------------------
An API resource policy can restrict access by IP or VPC endpoint. Evaluating
one properly means policy analysis, which this does not do, so a path on an API
carrying a resource policy is still reported -- annotated with
`HasResourcePolicy` so the analyst sees why it may be a false positive.
Authorization performed inside the backing Lambda is likewise invisible from
the control plane.

USAGE
-----
    - name: api-gateway-method-without-authorization
      resource: aws.rest-resource
      filters:
        - type: unauthenticated-method
"""
from c7n.filters import Filter
from c7n.resources.apigw import RestResource
from c7n.utils import local_session, type_schema


@RestResource.filter_registry.register("unauthenticated-method")
class UnauthenticatedMethod(Filter):
    """REST paths carrying a method that anyone can call."""

    schema = type_schema(
        "unauthenticated-method",
        ignore_methods={"type": "array", "items": {"type": "string"}},
        require_deployed={"type": "boolean"},
        include_private={"type": "boolean"},
    )
    permissions = ("apigateway:GET",)
    annotation = "c7n:UnauthenticatedMethods"

    def __init__(self, data, manager=None):
        super().__init__(data, manager)
        self._stage_cache = {}

    def process(self, resources, event=None):
        if not resources:
            return []
        ignored = {m.upper() for m in self.data.get("ignore_methods", ["OPTIONS"])}
        api_ids = {r["restApiId"] for r in resources if r.get("restApiId")}

        apis = self._describe_apis(api_ids)
        reachable = {aid for aid in api_ids if self._is_reachable(aid, apis.get(aid, {}))}

        # (api id, path) -> {verb: detail}, as each stage actually serves it.
        # With require_deployed false the live configuration is used instead,
        # which is what auditing an API that is not deployed yet means.
        vivo = not self.data.get("require_deployed", True)
        deployed = {}
        for aid in reachable:
            fuente = self._live_methods(aid) if vivo else self._deployed_methods(aid)
            for path, verbs in fuente.items():
                deployed.setdefault((aid, path), {}).update(verbs)

        matched = []
        for r in resources:
            if r["restApiId"] not in reachable:
                continue
            served = deployed.get((r["restApiId"], r.get("path")), {})
            abiertos = [
                verb
                for verb, detail in served.items()
                if verb.upper() not in ignored
                and detail.get("authorizationType") == "NONE"
                and detail.get("apiKeyRequired") is False
            ]
            if abiertos:
                r[self.annotation] = {
                    "Methods": sorted(abiertos),
                    "Path": r.get("path"),
                    "Stages": sorted(self._stage_names(r["restApiId"])),
                    "HasResourcePolicy": bool(apis.get(r["restApiId"], {}).get("policy")),
                }
                matched.append(r)
        return matched

    def _client(self):
        return local_session(self.manager.session_factory).client("apigateway")

    def _describe_apis(self, api_ids):
        client = self._client()
        out = {}
        for page in client.get_paginator("get_rest_apis").paginate():
            for api in page["items"]:
                if api["id"] in api_ids:
                    out[api["id"]] = api
        return out

    def _is_reachable(self, api_id, api):
        types = (api.get("endpointConfiguration") or {}).get("types") or []
        if "PRIVATE" in types and not self.data.get("include_private", False):
            return False
        if self.data.get("require_deployed", True) and not self._stages(api_id):
            return False
        return True

    def _live_methods(self, api_id):
        """path -> {verb: detail} from the live configuration.

        Only used with require_deployed false. One paginated call per API with
        embed=methods, instead of the one get_method per (path, verb) that the
        built-in rest-method filter does.
        """
        client = self._client()
        out = {}
        pages = client.get_paginator("get_resources").paginate(
            restApiId=api_id, embed=["methods"])
        for page in pages:
            for item in page["items"]:
                if item.get("resourceMethods"):
                    out[item.get("path")] = item["resourceMethods"]
        return out

    def _stages(self, api_id):
        if api_id in self._stage_cache:
            return self._stage_cache[api_id]
        try:
            item = self._client().get_stages(restApiId=api_id).get("item") or []
        except Exception:
            item = []
        self._stage_cache[api_id] = item
        return item

    def _stage_names(self, api_id):
        return {s.get("stageName") for s in self._stages(api_id) if s.get("stageName")}

    def _deployed_methods(self, api_id):
        """path -> {verb: detail}, as served by the stages.

        Several stages usually point at the same deployment, so deployment ids
        are deduplicated before asking.
        """
        client = self._client()
        out = {}
        ids = {s.get("deploymentId") for s in self._stages(api_id) if s.get("deploymentId")}
        for dep in ids:
            try:
                summary = client.get_deployment(
                    restApiId=api_id, deploymentId=dep,
                    embed=["apisummary"]).get("apiSummary") or {}
            except Exception:
                # A deployment can vanish between listing the stage and asking
                # for it. Skipping is right: what is gone serves nothing.
                continue
            for path, verbs in summary.items():
                out.setdefault(path, {}).update(verbs)
        return out
