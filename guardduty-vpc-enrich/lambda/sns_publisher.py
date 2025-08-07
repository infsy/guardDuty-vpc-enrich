import json
import logging
import os
import time
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class SNSPublisher:
    """Publisher for enriched GuardDuty alerts via SNS."""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.sns_client = boto3.client('sns')
        self.topic_arn = os.environ.get('SNS_TOPIC_ARN')
        self.max_retries = 3
        self.retry_delay = 1  # seconds
        
        if not self.topic_arn:
            raise ValueError("SNS_TOPIC_ARN environment variable not set")
    
    def publish_alert(
        self,
        enriched_alert: Dict[str, Any],
        correlation_id: str
    ) -> Dict[str, Any]:
        """
        Publish enriched alert to SNS topic.
        
        Args:
            enriched_alert: The enriched alert data
            correlation_id: Correlation ID for logging
            
        Returns:
            Dict containing SNS publish response
            
        Raises:
            Exception: If publishing fails after all retries
        """
        try:
            # Prepare message
            message_data = self._prepare_message(enriched_alert, correlation_id)
            
            # Publish with retry logic
            response = self._publish_with_retry(message_data, correlation_id)
            
            self.logger.info(
                f"Successfully published enriched alert to SNS",
                extra={
                    "correlation_id": correlation_id,
                    "message_id": response.get('MessageId'),
                    "topic_arn": self.topic_arn,
                    "finding_id": enriched_alert.get('finding_id')
                }
            )
            
            return response
            
        except Exception as e:
            self.logger.error(
                f"Failed to publish alert to SNS: {str(e)}",
                extra={
                    "correlation_id": correlation_id,
                    "finding_id": enriched_alert.get('finding_id')
                },
                exc_info=True
            )
            raise
    
    def _prepare_message(self, enriched_alert: Dict[str, Any], correlation_id: str) -> Dict[str, Any]:
        """Prepare SNS message with proper structure and attributes."""
        
        # Create compact message for SNS (due to size limits)
        compact_alert = self._create_compact_alert(enriched_alert)
        
        # Message attributes for filtering and routing
        message_attributes = {
            'finding_type': {
                'DataType': 'String',
                'StringValue': enriched_alert.get('finding_type', 'Unknown')
            },
            'severity': {
                'DataType': 'Number',
                'StringValue': str(enriched_alert.get('severity', 0))
            },
            'account_id': {
                'DataType': 'String',
                'StringValue': enriched_alert.get('account_id', 'Unknown')
            },
            'region': {
                'DataType': 'String',
                'StringValue': enriched_alert.get('region', 'Unknown')
            },
            'correlation_id': {
                'DataType': 'String',
                'StringValue': correlation_id
            },
            'alert_source': {
                'DataType': 'String',
                'StringValue': 'guardduty-vpc-enrichment'
            }
        }
        
        # Add network context attributes if available
        network_context = enriched_alert.get('network_context', {})
        if network_context:
            traffic_summary = network_context.get('traffic_summary', {})
            message_attributes['has_flow_logs'] = {
                'DataType': 'String',
                'StringValue': 'true'
            }
            message_attributes['suspicious_patterns_count'] = {
                'DataType': 'Number',
                'StringValue': str(len(network_context.get('suspicious_patterns', [])))
            }
            message_attributes['total_connections'] = {
                'DataType': 'Number',
                'StringValue': str(traffic_summary.get('total_connections', 0))
            }
        else:
            message_attributes['has_flow_logs'] = {
                'DataType': 'String',
                'StringValue': 'false'
            }
        
        # Create SNS message
        message = {
            'TopicArn': self.topic_arn,
            'Message': json.dumps(compact_alert, indent=2, default=str),
            'Subject': self._create_subject(enriched_alert),
            'MessageAttributes': message_attributes
        }
        
        return message
    
    def _create_compact_alert(self, enriched_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Create a compact version of the alert to fit SNS message size limits."""
        
        # Core finding information (always included)
        compact_alert = {
            'finding_id': enriched_alert.get('finding_id'),
            'severity': enriched_alert.get('severity'),
            'finding_type': enriched_alert.get('finding_type'),
            'timestamp': enriched_alert.get('timestamp'),
            'title': enriched_alert.get('title'),
            'description': enriched_alert.get('description')[:500] + '...' if len(enriched_alert.get('description', '')) > 500 else enriched_alert.get('description'),
            'region': enriched_alert.get('region'),
            'account_id': enriched_alert.get('account_id'),
            'resource': enriched_alert.get('resource', {})
        }
        
        # Network context summary
        network_context = enriched_alert.get('network_context', {})
        if network_context:
            compact_alert['network_summary'] = {
                'time_window': network_context.get('time_window'),
                'traffic_summary': network_context.get('traffic_summary', {}),
                'top_talkers_count': len(network_context.get('top_talkers', [])),
                'suspicious_patterns_count': len(network_context.get('suspicious_patterns', [])),
                'has_flow_logs': True
            }
            
            # Include top 3 suspicious patterns (summary only)
            patterns = network_context.get('suspicious_patterns', [])[:3]
            compact_alert['key_patterns'] = [
                {
                    'type': pattern.get('pattern_type'),
                    'description': pattern.get('description'),
                    'severity': pattern.get('severity_assessment', {}).get('level', 'unknown')
                }
                for pattern in patterns
            ]
        else:
            compact_alert['network_summary'] = {
                'has_flow_logs': False,
                'reason': 'No matching VPC Flow Logs found'
            }
        
        # Correlation insights summary
        correlation_insights = enriched_alert.get('correlation_insights', {})
        if correlation_insights:
            compact_alert['correlation_summary'] = {
                'quality': correlation_insights.get('correlation_quality', 'unknown'),
                'flow_logs_available': correlation_insights.get('flow_logs_availability', 'unknown'),
                'threat_validation': correlation_insights.get('threat_validation', {}).get('validation_status', 'unknown')
            }
        
        # Security recommendations (top 3 high priority)
        recommendations = enriched_alert.get('security_recommendations', [])
        high_priority_recommendations = [
            rec for rec in recommendations 
            if rec.get('priority') in ['critical', 'high']
        ][:3]
        
        if high_priority_recommendations:
            compact_alert['priority_recommendations'] = [
                {
                    'priority': rec.get('priority'),
                    'action': rec.get('action'),
                    'category': rec.get('category')
                }
                for rec in high_priority_recommendations
            ]
        
        # Analysis metadata
        analysis_metadata = enriched_alert.get('analysis_metadata', {})
        compact_alert['analysis_info'] = {
            'processing_time_ms': analysis_metadata.get('processing_time_ms'),
            'logs_analyzed': analysis_metadata.get('logs_analyzed', 0),
            'correlation_id': analysis_metadata.get('correlation_id'),
            'timestamp': analysis_metadata.get('timestamp')
        }
        
        return compact_alert
    
    def _create_subject(self, enriched_alert: Dict[str, Any]) -> str:
        """Create SNS message subject line."""
        severity = enriched_alert.get('severity', 0)
        finding_type = enriched_alert.get('finding_type', 'Unknown')
        account_id = enriched_alert.get('account_id', 'Unknown')
        
        # Determine severity label
        if severity >= 7.0:
            severity_label = "CRITICAL"
        elif severity >= 5.0:
            severity_label = "HIGH"
        elif severity >= 3.0:
            severity_label = "MEDIUM"
        else:
            severity_label = "LOW"
        
        # Check if flow logs were available
        network_context = enriched_alert.get('network_context', {})
        has_flow_logs = bool(network_context and network_context.get('traffic_summary', {}).get('total_connections', 0) > 0)
        flow_status = "ENRICHED" if has_flow_logs else "BASIC"
        
        subject = f"[{severity_label}] GuardDuty Alert ({flow_status}) - {finding_type} in {account_id}"
        
        # Truncate if too long (SNS subject limit is 100 characters)
        if len(subject) > 100:
            subject = subject[:97] + "..."
        
        return subject
    
    def _publish_with_retry(self, message_data: Dict[str, Any], correlation_id: str) -> Dict[str, Any]:
        """Publish message with retry logic."""
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                self.logger.debug(
                    f"Publishing to SNS (attempt {attempt + 1}/{self.max_retries})",
                    extra={"correlation_id": correlation_id}
                )
                
                response = self.sns_client.publish(**message_data)
                
                # Log success
                self.logger.debug(
                    f"SNS publish successful on attempt {attempt + 1}",
                    extra={
                        "correlation_id": correlation_id,
                        "message_id": response.get('MessageId')
                    }
                )
                
                return response
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                last_exception = e
                
                self.logger.warning(
                    f"SNS publish attempt {attempt + 1} failed: {error_code}",
                    extra={"correlation_id": correlation_id}
                )
                
                # Don't retry certain errors
                non_retryable_errors = [
                    'InvalidParameter',
                    'InvalidParameterValue',
                    'AuthorizationError',
                    'NotFound'
                ]
                
                if error_code in non_retryable_errors:
                    self.logger.error(
                        f"Non-retryable SNS error: {error_code}",
                        extra={"correlation_id": correlation_id}
                    )
                    raise e
                
                # Wait before retry (exponential backoff)
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    self.logger.debug(
                        f"Waiting {wait_time}s before retry",
                        extra={"correlation_id": correlation_id}
                    )
                    time.sleep(wait_time)
            
            except Exception as e:
                last_exception = e
                self.logger.warning(
                    f"SNS publish attempt {attempt + 1} failed with unexpected error: {str(e)}",
                    extra={"correlation_id": correlation_id}
                )
                
                # Wait before retry
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    time.sleep(wait_time)
        
        # All retries failed
        self.logger.error(
            f"All SNS publish attempts failed",
            extra={"correlation_id": correlation_id}
        )
        
        if last_exception:
            raise last_exception
        else:
            raise Exception("SNS publish failed after all retries")
    
    def validate_topic_access(self) -> bool:
        """
        Validate that the Lambda function has access to the SNS topic.
        
        Returns:
            bool: True if access is valid, False otherwise
        """
        try:
            # Try to get topic attributes (light operation)
            self.sns_client.get_topic_attributes(TopicArn=self.topic_arn)
            self.logger.info(f"SNS topic access validated: {self.topic_arn}")
            return True
            
        except ClientError as e:
            self.logger.error(f"SNS topic access validation failed: {str(e)}")
            return False
        
        except Exception as e:
            self.logger.error(f"Unexpected error validating SNS access: {str(e)}")
            return False
    
    def publish_test_message(self, correlation_id: str) -> bool:
        """
        Publish a test message to validate SNS functionality.
        
        Args:
            correlation_id: Correlation ID for logging
            
        Returns:
            bool: True if test message was published successfully
        """
        try:
            test_message = {
                'TopicArn': self.topic_arn,
                'Message': json.dumps({
                    'test_message': True,
                    'timestamp': time.time(),
                    'correlation_id': correlation_id,
                    'source': 'guardduty-vpc-enrichment-test'
                }),
                'Subject': '[TEST] GuardDuty VPC Enrichment - Connectivity Test',
                'MessageAttributes': {
                    'test_message': {
                        'DataType': 'String',
                        'StringValue': 'true'
                    },
                    'correlation_id': {
                        'DataType': 'String',
                        'StringValue': correlation_id
                    }
                }
            }
            
            response = self.sns_client.publish(**test_message)
            
            self.logger.info(
                f"Test message published successfully",
                extra={
                    "correlation_id": correlation_id,
                    "message_id": response.get('MessageId')
                }
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                f"Failed to publish test message: {str(e)}",
                extra={"correlation_id": correlation_id}
            )
            return False