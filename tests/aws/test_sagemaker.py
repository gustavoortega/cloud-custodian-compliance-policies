"""Behavioural tests for policies/aws/sagemaker.yml.

Offline: no AWS credentials, no network.

Resource shapes:
  - `aws.sagemaker-notebook` -> describe_notebook_instance: NotebookInstanceArn
    (c7n's id), NotebookInstanceName, DirectInternetAccess/RootAccess as the
    strings 'Enabled'/'Disabled', KmsKeyId, and
    InstanceMetadataServiceConfiguration.MinimumInstanceMetadataServiceVersion
    as a STRING ('1'/'2'), not a number.
  - `aws.sagemaker-*-job-definition` -> describe_*_job_definition:
    JobDefinitionArn (c7n's id), JobDefinitionName, NetworkConfig{...},
    JobResources.ClusterConfig{InstanceCount, InstanceType, VolumeSizeInGB}.
  - `aws.sagemaker-model` -> describe_model: ModelArn (c7n's id), ModelName,
    and either PrimaryContainer (single-container) or Containers (inference
    pipeline), never both.

The ARNs are unique per resource because c7n's `or:` deduplicates matches by
the resource-type id, which for all three types above is the ARN. Assertions
are on the short *Name* field for readability, and SORTED: `or:` rebuilds its
result from a Python `set` of ids, so the order varies between processes.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/sagemaker.yml'


def notebook(name, **kw):
    return {
        'NotebookInstanceArn':
            f'arn:aws:sagemaker:us-east-1:111111111111:notebook-instance/{name}',
        'NotebookInstanceName': name,
        'NotebookInstanceStatus': 'InService',
        **kw,
    }


def job_def(name, **kw):
    return {
        'JobDefinitionArn':
            f'arn:aws:sagemaker:us-east-1:111111111111:job-definition/{name}',
        'JobDefinitionName': name,
        **kw,
    }


def model(name, **kw):
    return {
        'ModelArn': f'arn:aws:sagemaker:us-east-1:111111111111:model/{name}',
        'ModelName': name,
        **kw,
    }


def cluster(instance_count):
    return {'ClusterConfig': {'InstanceCount': instance_count,
                              'InstanceType': 'ml.m5.large',
                              'VolumeSizeInGB': 20}}


def matched(policy, resources, key):
    return sorted(r[key] for r in run_policy(POLICIES, policy, resources))


def test_sagemaker_notebook_direct_internet_access():
    resources = [
        notebook('matches', DirectInternetAccess='Enabled'),
        notebook('clean', DirectInternetAccess='Disabled'),
        # KNOWN LIMITATION: single equality against the string 'Enabled' with
        # no `absent` branch, so a notebook the field never came back for is
        # reported as compliant.
        notebook('key-absent'),
    ]
    assert matched('sagemaker-notebook-direct-internet-access', resources,
                   'NotebookInstanceName') == ['matches']


def test_sagemaker_notebook_root_access_enabled():
    resources = [
        notebook('matches', RootAccess='Enabled'),
        notebook('clean', RootAccess='Disabled'),
        # KNOWN LIMITATION: no `absent` branch -- a notebook missing RootAccess
        # reads as compliant.
        notebook('key-absent'),
    ]
    assert matched('sagemaker-notebook-root-access-enabled', resources,
                   'NotebookInstanceName') == ['matches']


def test_sagemaker_notebook_unencrypted():
    resources = [
        # `value: absent` IS the match condition: no CMK on the volume
        notebook('matches'),
        notebook('clean',
                 KmsKeyId='arn:aws:kms:us-east-1:111111111111:key/'
                          '12345678-1234-1234-1234-123456789012'),
    ]
    assert matched('sagemaker-notebook-unencrypted', resources,
                   'NotebookInstanceName') == ['matches']


def test_sagemaker_notebook_allows_imdsv1():
    resources = [
        notebook('imdsv1', InstanceMetadataServiceConfiguration={
            'MinimumInstanceMetadataServiceVersion': '1'}),
        notebook('clean', InstanceMetadataServiceConfiguration={
            'MinimumInstanceMetadataServiceVersion': '2'}),
        # the block is missing on notebooks created before the setting existed,
        # and its absence means v1 is accepted -- caught by the `or: absent` branch
        notebook('key-absent'),
    ]
    assert matched('sagemaker-notebook-allows-imdsv1', resources,
                   'NotebookInstanceName') == ['imdsv1', 'key-absent']


def _network_config_cases(field):
    return [
        job_def('matches', NetworkConfig={field: False}),
        job_def('clean', NetworkConfig={field: True}),
        # NetworkConfig is absent on a job definition created without an
        # explicit network block -- caught by the `or: absent` branch
        job_def('networkconfig-absent'),
    ]


def test_sagemaker_data_quality_job_definition_traffic_encryption_disabled():
    resources = _network_config_cases('EnableInterContainerTrafficEncryption')
    assert matched(
        'sagemaker-data-quality-job-definition-traffic-encryption-disabled',
        resources, 'JobDefinitionName') == ['matches', 'networkconfig-absent']


def test_sagemaker_data_quality_job_definition_network_isolation_disabled():
    resources = _network_config_cases('EnableNetworkIsolation')
    assert matched(
        'sagemaker-data-quality-job-definition-network-isolation-disabled',
        resources, 'JobDefinitionName') == ['matches', 'networkconfig-absent']


def test_sagemaker_model_explainability_job_definition_traffic_encryption_disabled():
    resources = _network_config_cases('EnableInterContainerTrafficEncryption')
    assert matched(
        'sagemaker-model-explainability-job-definition-traffic-encryption-disabled',
        resources, 'JobDefinitionName') == ['matches', 'networkconfig-absent']


def test_sagemaker_model_bias_job_definition_network_isolation_disabled():
    resources = _network_config_cases('EnableNetworkIsolation')
    assert matched(
        'sagemaker-model-bias-job-definition-network-isolation-disabled',
        resources, 'JobDefinitionName') == ['matches', 'networkconfig-absent']


def test_sagemaker_model_quality_job_definition_traffic_encryption_disabled():
    resources = _network_config_cases('EnableInterContainerTrafficEncryption')
    assert matched(
        'sagemaker-model-quality-job-definition-traffic-encryption-disabled',
        resources, 'JobDefinitionName') == ['matches', 'networkconfig-absent']


def test_sagemaker_model_bias_job_definition_traffic_encryption_disabled():
    field = 'EnableInterContainerTrafficEncryption'
    resources = [
        job_def('matches', JobResources=cluster(2), NetworkConfig={field: False}),
        job_def('clean', JobResources=cluster(2), NetworkConfig={field: True}),
        # below 2 instances the control does not apply
        job_def('single-instance', JobResources=cluster(1),
                NetworkConfig={field: False}),
        job_def('networkconfig-absent', JobResources=cluster(2)),
        # KNOWN LIMITATION: `op: ge` against an absent
        # JobResources.ClusterConfig.InstanceCount resolves to None and never
        # matches, so a job definition missing JobResources is dropped by the
        # first filter regardless of its encryption setting.
        job_def('jobresources-absent', NetworkConfig={field: False}),
    ]
    assert matched(
        'sagemaker-model-bias-job-definition-traffic-encryption-disabled',
        resources, 'JobDefinitionName') == ['matches', 'networkconfig-absent']


def test_sagemaker_model_private_registry_not_used():
    resources = [
        # ImageConfig unset unless the model opts into a VPC registry
        model('no-imageconfig', PrimaryContainer={
            'Image': '111111111111.dkr.ecr.us-east-1.amazonaws.com/infer:latest'}),
        model('platform-mode', PrimaryContainer={
            'Image': '111111111111.dkr.ecr.us-east-1.amazonaws.com/infer:latest',
            'ImageConfig': {'RepositoryAccessMode': 'Platform'}}),
        model('clean', PrimaryContainer={
            'Image': '111111111111.dkr.ecr.us-east-1.amazonaws.com/infer:latest',
            'ImageConfig': {'RepositoryAccessMode': 'Vpc',
                            'RepositoryAuthConfig': {
                                'RepositoryCredentialsProviderArn':
                                    'arn:aws:lambda:us-east-1:111111111111:function:creds'}}}),
    ]
    assert matched('sagemaker-model-private-registry-not-used', resources,
                   'ModelName') == ['no-imageconfig', 'platform-mode']


def test_sagemaker_model_multi_container_private_registry_not_used():
    vpc = {'RepositoryAccessMode': 'Vpc'}
    resources = [
        model('matches', Containers=[
            {'Image': 'a', 'ImageConfig': vpc},
            {'Image': 'b', 'ImageConfig': {'RepositoryAccessMode': 'Platform'}}]),
        model('clean', Containers=[{'Image': 'a', 'ImageConfig': vpc}]),
        # a container with no ImageConfig at all also fails the != 'Vpc' test
        model('imageconfig-absent', Containers=[{'Image': 'a'}]),
        # single-container models carry PrimaryContainer, not Containers, and
        # are excluded by the `Containers present` filter
        model('single-container', PrimaryContainer={'Image': 'a'}),
    ]
    assert matched('sagemaker-model-multi-container-private-registry-not-used',
                   resources, 'ModelName') == ['imageconfig-absent', 'matches']
