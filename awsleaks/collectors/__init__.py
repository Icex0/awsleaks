from awsleaks.collectors.lambda_collector import LambdaCollector
from awsleaks.collectors.codecommit import CodeCommitCollector
from awsleaks.collectors.codebuild import CodeBuildCollector
from awsleaks.collectors.codepipeline import CodePipelineCollector
from awsleaks.collectors.glue import GlueCollector
from awsleaks.collectors.ecs import ECSCollector
from awsleaks.collectors.ec2 import EC2Collector
from awsleaks.collectors.cloudformation import CloudFormationCollector
from awsleaks.collectors.stepfunctions import StepFunctionsCollector
from awsleaks.collectors.beanstalk import BeanstalkCollector
from awsleaks.collectors.sagemaker import SageMakerCollector
from awsleaks.collectors.ssm import SSMCollector
from awsleaks.collectors.apigateway import APIGatewayCollector
from awsleaks.collectors.appsync import AppSyncCollector
from awsleaks.collectors.batch import BatchCollector
from awsleaks.collectors.amplify import AmplifyCollector
from awsleaks.collectors.s3 import S3Collector

GLOBAL_COLLECTORS = {"s3"}

ALL_COLLECTORS = {
    "lambda": LambdaCollector,
    "codecommit": CodeCommitCollector,
    "codebuild": CodeBuildCollector,
    "codepipeline": CodePipelineCollector,
    "glue": GlueCollector,
    "stepfunctions": StepFunctionsCollector,
    "ecs": ECSCollector,
    "ec2": EC2Collector,
    "cloudformation": CloudFormationCollector,
    "beanstalk": BeanstalkCollector,
    "sagemaker": SageMakerCollector,
    "ssm": SSMCollector,
    "apigateway": APIGatewayCollector,
    "appsync": AppSyncCollector,
    "batch": BatchCollector,
    "amplify": AmplifyCollector,
    "s3": S3Collector,
}
