import json
import logging
import os
import time
from typing import Dict, Any
import boto3
from botocore.exceptions import ClientError

from guardduty_parser import GuardDutyParser
from flow_logs_analyzer import FlowLogsAnalyzer
from enrichment_engine import EnrichmentEngine
from sns_publisher import SNSPublisher

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.basicConfig(
    level=getattr(logging, log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize AWS clients
cloudwatch = boto3.client('cloudwatch')

# Initialize components
guardduty_parser = GuardDutyParser()
flow_analyzer = FlowLogsAnalyzer()
enrichment_engine = EnrichmentEngine()
sns_publisher = SNSPublisher()


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Main Lambda handler for GuardDuty VPC Flow Logs enrichment.
    
    Args:
        event: EventBridge event containing GuardDuty finding
        context: Lambda context object
        
    Returns:
        Dict containing processing results
    """
    start_time = time.time()
    correlation_id = context.aws_request_id
    
    logger.info(
        f"Starting GuardDuty enrichment processing",
        extra={
            "correlation_id": correlation_id,
            "event_source": event.get('source'),
            "detail_type": event.get('detail-type')
        }
    )
    
    try:
        # Parse GuardDuty finding
        finding_data = guardduty_parser.parse_finding(event)
        logger.info(
            f"Parsed GuardDuty finding: {finding_data.finding_id}",
            extra={
                "correlation_id": correlation_id,
                "finding_id": finding_data.finding_id,
                "severity": finding_data.severity,
                "finding_type": finding_data.finding_type
            }
        )
        
        # Check severity threshold
        severity_threshold = float(os.environ.get('SEVERITY_THRESHOLD', '4.0'))
        if finding_data.severity < severity_threshold:
            logger.info(
                f"Finding severity {finding_data.severity} below threshold {severity_threshold}, skipping",
                extra={"correlation_id": correlation_id, "finding_id": finding_data.finding_id}
            )
            return _create_response("skipped", "Below severity threshold", correlation_id)
        
        # Analyze VPC Flow Logs
        flow_analysis = flow_analyzer.analyze_flows(
            finding_data=finding_data,
            correlation_id=correlation_id
        )
        
        if not flow_analysis:
            logger.warning(
                f"No flow logs found for finding {finding_data.finding_id}",
                extra={"correlation_id": correlation_id, "finding_id": finding_data.finding_id}
            )
        
        # Enrich the finding with flow logs analysis
        enriched_alert = enrichment_engine.enrich_finding(
            finding_data=finding_data,
            flow_analysis=flow_analysis,
            correlation_id=correlation_id
        )
        
        # Publish enriched alert
        sns_result = sns_publisher.publish_alert(
            enriched_alert=enriched_alert,
            correlation_id=correlation_id
        )
        
        # Calculate processing time
        processing_time = int((time.time() - start_time) * 1000)
        
        # Send custom metrics
        _send_metrics(
            processing_time=processing_time,
            finding_severity=finding_data.severity,
            logs_analyzed=flow_analysis.get('logs_analyzed', 0) if flow_analysis else 0,
            patterns_detected=len(enriched_alert.get('network_context', {}).get('suspicious_patterns', []))
        )
        
        logger.info(
            f"Processing completed successfully",
            extra={
                "correlation_id": correlation_id,
                "finding_id": finding_data.finding_id,
                "processing_time_ms": processing_time,
                "logs_analyzed": flow_analysis.get('logs_analyzed', 0) if flow_analysis else 0
            }
        )
        
        return _create_response(
            status="success",
            message="Finding enriched and published successfully",
            correlation_id=correlation_id,
            additional_data={
                "finding_id": finding_data.finding_id,
                "processing_time_ms": processing_time,
                "sns_message_id": sns_result.get('MessageId')
            }
        )
        
    except ValueError as e:
        logger.error(
            f"Validation error: {str(e)}",
            extra={"correlation_id": correlation_id},
            exc_info=True
        )
        _send_error_metric("validation_error")
        return _create_response("error", f"Validation error: {str(e)}", correlation_id)
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        logger.error(
            f"AWS service error: {error_code} - {str(e)}",
            extra={"correlation_id": correlation_id},
            exc_info=True
        )
        _send_error_metric(f"aws_error_{error_code}")
        return _create_response("error", f"AWS service error: {error_code}", correlation_id)
        
    except Exception as e:
        logger.error(
            f"Unexpected error: {str(e)}",
            extra={"correlation_id": correlation_id},
            exc_info=True
        )
        _send_error_metric("unexpected_error")
        return _create_response("error", f"Unexpected error: {str(e)}", correlation_id)


def _create_response(status: str, message: str, correlation_id: str, additional_data: Dict = None) -> Dict[str, Any]:
    """Create standardized response object."""
    response = {
        "status": status,
        "message": message,
        "correlation_id": correlation_id,
        "timestamp": int(time.time())
    }
    
    if additional_data:
        response.update(additional_data)
        
    return response


def _send_metrics(processing_time: int, finding_severity: float, logs_analyzed: int, patterns_detected: int) -> None:
    """Send custom CloudWatch metrics."""
    try:
        cloudwatch.put_metric_data(
            Namespace='GuardDuty/Enrichment',
            MetricData=[
                {
                    'MetricName': 'ProcessingDuration',
                    'Value': processing_time,
                    'Unit': 'Milliseconds',
                    'Dimensions': [
                        {
                            'Name': 'Environment',
                            'Value': os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown')
                        }
                    ]
                },
                {
                    'MetricName': 'FindingSeverity',
                    'Value': finding_severity,
                    'Unit': 'None'
                },
                {
                    'MetricName': 'FlowLogsAnalyzed',
                    'Value': logs_analyzed,
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'SuspiciousPatternsDetected',
                    'Value': patterns_detected,
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'EnrichmentSuccess',
                    'Value': 1,
                    'Unit': 'Count'
                }
            ]
        )
    except Exception as e:
        logger.warning(f"Failed to send metrics: {str(e)}")


def _send_error_metric(error_type: str) -> None:
    """Send error metric to CloudWatch."""
    try:
        cloudwatch.put_metric_data(
            Namespace='GuardDuty/Enrichment',
            MetricData=[
                {
                    'MetricName': 'EnrichmentFailure',
                    'Value': 1,
                    'Unit': 'Count',
                    'Dimensions': [
                        {
                            'Name': 'ErrorType',
                            'Value': error_type
                        },
                        {
                            'Name': 'Environment',
                            'Value': os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown')
                        }
                    ]
                }
            ]
        )
    except Exception as e:
        logger.warning(f"Failed to send error metric: {str(e)}")