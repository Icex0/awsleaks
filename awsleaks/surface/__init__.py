from awsleaks.surface.security_groups import SecurityGroupCheck
from awsleaks.surface.ec2 import EC2Check
from awsleaks.surface.elb import ELBCheck
from awsleaks.surface.rds import RDSCheck
from awsleaks.surface.redshift import RedshiftCheck
from awsleaks.surface.s3 import S3Check
from awsleaks.surface.apigateway import APIGatewayCheck
from awsleaks.surface.lambda_urls import LambdaURLCheck
from awsleaks.surface.opensearch import OpenSearchCheck
from awsleaks.surface.eks import EKSCheck
from awsleaks.surface.ecs import ECSCheck
from awsleaks.surface.ebs_snapshots import EBSSnapshotCheck
from awsleaks.surface.rds_snapshots import RDSSnapshotCheck
from awsleaks.surface.amis import AMICheck
from awsleaks.surface.ecr import ECRCheck
from awsleaks.surface.sqs import SQSCheck
from awsleaks.surface.sns import SNSCheck
from awsleaks.surface.ssm_documents import SSMDocumentCheck
from awsleaks.surface.mq import MQCheck
from awsleaks.surface.transfer import TransferCheck
from awsleaks.surface.route53 import Route53Check
from awsleaks.surface.check_imdsv1_roles import IMDSv1RoleCheck

GLOBAL_CHECKS = {"s3", "route53"}

ALL_CHECKS = {
    "security-groups": SecurityGroupCheck,
    "ec2": EC2Check,
    "elb": ELBCheck,
    "rds": RDSCheck,
    "redshift": RedshiftCheck,
    "s3": S3Check,
    "apigateway": APIGatewayCheck,
    "lambda-urls": LambdaURLCheck,
    "opensearch": OpenSearchCheck,
    "eks": EKSCheck,
    "ecs": ECSCheck,
    "ebs-snapshots": EBSSnapshotCheck,
    "rds-snapshots": RDSSnapshotCheck,
    "amis": AMICheck,
    "ecr": ECRCheck,
    "sqs": SQSCheck,
    "sns": SNSCheck,
    "ssm-documents": SSMDocumentCheck,
    "mq": MQCheck,
    "transfer": TransferCheck,
    "route53": Route53Check,
    "imdsv1-roles": IMDSv1RoleCheck,
}
