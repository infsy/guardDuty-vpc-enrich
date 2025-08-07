from aws_cdk import (
    Duration,
    Stack,
    aws_lambda as _lambda,
    aws_events as events,
    aws_events_targets as targets,
    aws_sns as sns,
    aws_iam as iam,
    aws_logs as logs,
    aws_kms as kms,
    aws_sqs as sqs,
    CfnParameter,
    CfnOutput,
    RemovalPolicy
)
from constructs import Construct
from config.environment_config import EnvironmentConfig


class GuardDutyEnrichmentStack(Stack):
    def __init__(
        self, 
        scope: Construct, 
        construct_id: str, 
        environment: str = "dev",
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.config = EnvironmentConfig(environment)
        
        # Parameters
        self._create_parameters()
        
        # KMS Key for encryption
        self.kms_key = self._create_kms_key()
        
        # SNS Topic and DLQ
        self.sns_topic, self.dlq = self._create_sns_resources()
        
        # Lambda Function
        self.lambda_function = self._create_lambda_function()
        
        # EventBridge Rule
        self.eventbridge_rule = self._create_eventbridge_rule()
        
        # CloudWatch Dashboard
        self._create_cloudwatch_resources()
        
        # Outputs
        self._create_outputs()
    
    def _create_parameters(self) -> None:
        self.flow_logs_bucket_param = CfnParameter(
            self, "FlowLogsBucketName",
            type="String",
            description="S3 bucket containing VPC Flow Logs",
            default="my-vpc-flow-logs-bucket"
        )
        
        self.sns_topic_param = CfnParameter(
            self, "SnsTopicArn",
            type="String",
            description="SNS Topic ARN for enriched alerts (leave empty to create new)",
            default=""
        )
        
        self.severity_threshold_param = CfnParameter(
            self, "SeverityThreshold",
            type="Number",
            description="Minimum GuardDuty severity to process (0-8)",
            default=self.config.severity_threshold,
            min_value=0,
            max_value=8
        )
    
    def _create_kms_key(self) -> kms.Key:
        key = kms.Key(
            self, "GuardDutyEnrichmentKey",
            description="KMS key for GuardDuty enrichment encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY if self.config.environment == "dev" else RemovalPolicy.RETAIN
        )
        
        key.add_alias(f"alias/guardduty-enrichment-{self.config.environment}")
        
        return key
    
    def _create_sns_resources(self) -> tuple[sns.Topic, sqs.Queue]:
        # Dead Letter Queue
        dlq = sqs.Queue(
            self, "EnrichmentDLQ",
            queue_name=f"guardduty-enrichment-dlq-{self.config.environment}",
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=self.kms_key,
            retention_period=Duration.days(14),
            visibility_timeout=Duration.minutes(6)
        )
        
        # SNS Topic (create new if ARN not provided)
        topic = sns.Topic(
            self, "EnrichmentTopic",
            topic_name=f"guardduty-enrichment-{self.config.environment}",
            display_name="GuardDuty Enrichment Alerts",
            master_key=self.kms_key
        )
        
        # Add dead letter queue to topic
        topic.add_subscription(
            sns.SqsSubscription(
                dlq,
                dead_letter_queue=dlq,
                raw_message_delivery=True
            )
        )
        
        return topic, dlq
    
    def _create_lambda_function(self) -> _lambda.Function:
        # Lambda execution role
        lambda_role = iam.Role(
            self, "LambdaExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ],
            inline_policies={
                "GuardDutyEnrichmentPolicy": iam.PolicyDocument(
                    statements=[
                        # S3 permissions for VPC Flow Logs
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "s3:GetObject",
                                "s3:ListBucket"
                            ],
                            resources=[
                                f"arn:aws:s3:::{self.flow_logs_bucket_param.value_as_string}",
                                f"arn:aws:s3:::{self.flow_logs_bucket_param.value_as_string}/*"
                            ]
                        ),
                        # SNS permissions
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["sns:Publish"],
                            resources=[self.sns_topic.topic_arn]
                        ),
                        # KMS permissions
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "kms:Decrypt",
                                "kms:DescribeKey",
                                "kms:Encrypt",
                                "kms:GenerateDataKey",
                                "kms:ReEncrypt*"
                            ],
                            resources=[self.kms_key.key_arn]
                        ),
                        # CloudWatch metrics
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "cloudwatch:PutMetricData"
                            ],
                            resources=["*"],
                            conditions={
                                "StringEquals": {
                                    "cloudwatch:namespace": "GuardDuty/Enrichment"
                                }
                            }
                        )
                    ]
                )
            }
        )
        
        # Add X-Ray permissions if enabled
        if self.config.enable_xray:
            lambda_role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AWSXRayDaemonWriteAccess")
            )
        
        # Lambda function
        lambda_function = _lambda.Function(
            self, "GuardDutyEnrichmentFunction",
            function_name=f"guardduty-vpc-enrichment-{self.config.environment}",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            code=_lambda.Code.from_asset("lambda"),
            role=lambda_role,
            timeout=Duration.seconds(self.config.lambda_timeout),
            memory_size=self.config.lambda_memory,
            environment={
                "SNS_TOPIC_ARN": self.sns_topic.topic_arn,
                "FLOW_LOGS_BUCKET": self.flow_logs_bucket_param.value_as_string,
                "TIME_WINDOW_BEFORE": str(self.config.time_window_before),
                "TIME_WINDOW_AFTER": str(self.config.time_window_after),
                "LOG_LEVEL": self.config.log_level,
                "SEVERITY_THRESHOLD": str(self.config.severity_threshold),
                "KMS_KEY_ID": self.kms_key.key_id
            },
            tracing=_lambda.Tracing.ACTIVE if self.config.enable_xray else _lambda.Tracing.DISABLED,
            reserved_concurrent_executions=10,
            dead_letter_queue=self.dlq
        )
        
        # CloudWatch Log Group with retention
        logs.LogGroup(
            self, "LambdaLogGroup",
            log_group_name=f"/aws/lambda/{lambda_function.function_name}",
            retention=logs.RetentionDays(f"_{self.config.retention_days}_DAYS"),
            removal_policy=RemovalPolicy.DESTROY
        )
        
        return lambda_function
    
    def _create_eventbridge_rule(self) -> events.Rule:
        # EventBridge rule for GuardDuty findings
        rule = events.Rule(
            self, "GuardDutyFindingRule",
            rule_name=f"guardduty-enrichment-rule-{self.config.environment}",
            description="Trigger Lambda on GuardDuty findings",
            event_pattern=events.EventPattern(
                source=["aws.guardduty"],
                detail_type=["GuardDuty Finding"],
                detail={
                    "severity": [
                        {"numeric": [">=", self.severity_threshold_param.value_as_number]}
                    ]
                }
            )
        )
        
        # Add Lambda as target
        rule.add_target(
            targets.LambdaFunction(
                self.lambda_function,
                retry_attempts=2,
                max_event_age=Duration.hours(2)
            )
        )
        
        return rule
    
    def _create_cloudwatch_resources(self) -> None:
        # Custom metrics for monitoring
        # These will be created by the Lambda function, but we define alarms here
        
        # Error rate alarm
        error_alarm = logs.MetricFilter(
            self, "ErrorMetricFilter",
            log_group=logs.LogGroup.from_log_group_name(
                self, "LambdaLogGroupRef",
                f"/aws/lambda/{self.lambda_function.function_name}"
            ),
            metric_name="EnrichmentErrors",
            metric_namespace="GuardDuty/Enrichment",
            metric_value="1",
            filter_pattern=logs.FilterPattern.literal("[timestamp, request_id, level=\"ERROR\", ...]")
        )
        
        # Duration metric filter
        duration_filter = logs.MetricFilter(
            self, "DurationMetricFilter",
            log_group=logs.LogGroup.from_log_group_name(
                self, "LambdaLogGroupRefDuration",
                f"/aws/lambda/{self.lambda_function.function_name}"
            ),
            metric_name="EnrichmentDuration",
            metric_namespace="GuardDuty/Enrichment",
            metric_value="$duration",
            filter_pattern=logs.FilterPattern.literal("[timestamp, request_id, level, msg=\"Processing completed\", duration]")
        )
    
    def _create_outputs(self) -> None:
        CfnOutput(
            self, "LambdaFunctionArn",
            value=self.lambda_function.function_arn,
            description="GuardDuty Enrichment Lambda Function ARN"
        )
        
        CfnOutput(
            self, "SNSTopicArn",
            value=self.sns_topic.topic_arn,
            description="SNS Topic ARN for enriched alerts"
        )
        
        CfnOutput(
            self, "EventBridgeRuleArn",
            value=self.eventbridge_rule.rule_arn,
            description="EventBridge Rule ARN"
        )
        
        CfnOutput(
            self, "KMSKeyId",
            value=self.kms_key.key_id,
            description="KMS Key ID for encryption"
        )
        
        CfnOutput(
            self, "DLQUrl",
            value=self.dlq.queue_url,
            description="Dead Letter Queue URL"
        )
        
        # Apply tags to all resources
        for key, value in self.config.tags.items():
            self.tags.set_tag(key, value)