"""Privilege escalation paths — auto-generated from pathfinding.cloud data.

Source: https://github.com/DataDog/pathfinding.cloud
Total paths: 66
"""

# Solo permissions — single permission is enough for escalation (22 paths)
SOLO_PRIVESC = {
    "apprunner:UpdateService",
    "cloudformation:UpdateStack",
    "codebuild:StartBuild",
    "codebuild:StartBuildBatch",
    "ec2-instance-connect:SendSSHPublicKey",
    "glue:UpdateDevEndpoint",
    "iam:AddUserToGroup",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:CreatePolicyVersion",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:UpdateLoginProfile",
    "lambda:UpdateFunctionCode",
    "sagemaker:CreatePresignedNotebookInstanceUrl",
    "ssm:SendCommand",
    "ssm:StartSession",
}

# iam:PassRole combinations — require PassRole + service permission(s) (26 paths)
PASSROLE_COMBOS = [
    frozenset({"apprunner:CreateService", "iam:PassRole"}),
    frozenset({"bedrock-agentcore:CreateCodeInterpreter", "bedrock-agentcore:StartCodeInterpreterSession", "iam:PassRole"}),
    frozenset({"cloudformation:CreateStack", "iam:PassRole"}),
    frozenset({"cloudformation:CreateStackInstances", "cloudformation:CreateStackSet", "iam:PassRole"}),
    frozenset({"cloudformation:UpdateStackSet", "iam:PassRole"}),
    frozenset({"codebuild:CreateProject", "codebuild:StartBuild", "iam:PassRole"}),
    frozenset({"codebuild:CreateProject", "codebuild:StartBuildBatch", "iam:PassRole"}),
    frozenset({"datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "iam:PassRole"}),
    frozenset({"ec2:RequestSpotInstances", "iam:PassRole"}),
    frozenset({"ec2:RunInstances", "iam:PassRole"}),
    frozenset({"ecs:CreateCluster", "ecs:CreateService", "ecs:RegisterTaskDefinition", "iam:PassRole"}),
    frozenset({"ecs:CreateCluster", "ecs:RegisterTaskDefinition", "ecs:RunTask", "iam:PassRole"}),
    frozenset({"ecs:CreateService", "ecs:RegisterTaskDefinition", "iam:PassRole"}),
    frozenset({"ecs:RegisterTaskDefinition", "ecs:RunTask", "iam:PassRole"}),
    frozenset({"ecs:RegisterTaskDefinition", "ecs:StartTask", "iam:PassRole"}),
    frozenset({"glue:CreateDevEndpoint", "iam:PassRole"}),
    frozenset({"glue:CreateJob", "glue:CreateTrigger", "iam:PassRole"}),
    frozenset({"glue:CreateJob", "glue:StartJobRun", "iam:PassRole"}),
    frozenset({"glue:CreateTrigger", "glue:UpdateJob", "iam:PassRole"}),
    frozenset({"glue:StartJobRun", "glue:UpdateJob", "iam:PassRole"}),
    frozenset({"iam:PassRole", "lambda:AddPermission", "lambda:CreateFunction"}),
    frozenset({"iam:PassRole", "lambda:CreateEventSourceMapping", "lambda:CreateFunction"}),
    frozenset({"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"}),
    frozenset({"iam:PassRole", "sagemaker:CreateNotebookInstance"}),
    frozenset({"iam:PassRole", "sagemaker:CreateProcessingJob"}),
    frozenset({"iam:PassRole", "sagemaker:CreateTrainingJob"}),
]

# Other multi-permission combos — no PassRole needed (17 paths)
OTHER_COMBOS = [
    frozenset({"bedrock-agentcore:InvokeCodeInterpreter", "bedrock-agentcore:StartCodeInterpreterSession"}),
    frozenset({"cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet"}),
    frozenset({"ec2:CreateLaunchTemplateVersion", "ec2:ModifyLaunchTemplate"}),
    frozenset({"ec2:ModifyInstanceAttribute", "ec2:StartInstances", "ec2:StopInstances"}),
    frozenset({"ecs:DescribeTasks", "ecs:ExecuteCommand"}),
    frozenset({"iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy"}),
    frozenset({"iam:AttachRolePolicy", "sts:AssumeRole"}),
    frozenset({"iam:AttachUserPolicy", "iam:CreateAccessKey"}),
    frozenset({"iam:CreateAccessKey", "iam:DeleteAccessKey"}),
    frozenset({"iam:CreateAccessKey", "iam:PutUserPolicy"}),
    frozenset({"iam:CreatePolicyVersion", "iam:UpdateAssumeRolePolicy"}),
    frozenset({"iam:CreatePolicyVersion", "sts:AssumeRole"}),
    frozenset({"iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"}),
    frozenset({"iam:PutRolePolicy", "sts:AssumeRole"}),
    frozenset({"lambda:AddPermission", "lambda:UpdateFunctionCode"}),
    frozenset({"lambda:InvokeFunction", "lambda:UpdateFunctionCode"}),
    frozenset({"sagemaker:CreateNotebookInstanceLifecycleConfig", "sagemaker:StartNotebookInstance", "sagemaker:StopNotebookInstance", "sagemaker:UpdateNotebookInstance"}),
]

# STS — assume role
STS_PRIVESC = {
    "sts:AssumeRole",
}

# All combo paths (PassRole + Other) for unified lookup
ALL_COMBOS = PASSROLE_COMBOS + OTHER_COMBOS
