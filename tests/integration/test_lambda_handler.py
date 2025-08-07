import pytest
from unittest.mock import Mock, patch, MagicMock
import json
import sys
import os
from datetime import datetime

# Add lambda directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'lambda'))

from handler import lambda_handler


class TestLambdaHandler:
    
    def setup_method(self):
        """Setup test environment variables."""
        self.env_patcher = patch.dict(os.environ, {
            'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-topic',
            'FLOW_LOGS_BUCKET': 'test-flow-logs-bucket',
            'TIME_WINDOW_BEFORE': '15',
            'TIME_WINDOW_AFTER': '15',
            'LOG_LEVEL': 'INFO',
            'SEVERITY_THRESHOLD': '4.0',
            'KMS_KEY_ID': 'test-key-id'
        })
        self.env_patcher.start()
    
    def teardown_method(self):
        """Cleanup environment patches."""
        self.env_patcher.stop()
    
    @pytest.fixture
    def sample_guardduty_event(self):
        """Create a sample GuardDuty EventBridge event."""
        return {
            "version": "0",
            "id": "12345678-1234-1234-1234-123456789012",
            "detail-type": "GuardDuty Finding",
            "source": "aws.guardduty",
            "account": "123456789012",
            "time": "2024-01-15T12:30:45Z",
            "region": "us-east-1",
            "detail": {
                "schemaVersion": "2.0",
                "accountId": "123456789012",
                "region": "us-east-1",
                "partition": "aws",
                "id": "test-finding-id-12345",
                "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/12345/finding/test-finding-id-12345",
                "type": "Recon:EC2/PortProbeUnprotectedPort",
                "resource": {
                    "resourceType": "Instance",
                    "instanceDetails": {
                        "instanceId": "i-1234567890abcdef0",
                        "instanceType": "t3.micro",
                        "networkInterfaces": [
                            {
                                "networkInterfaceId": "eni-12345678",
                                "privateIpAddress": "10.0.1.100",
                                "publicIp": "203.0.113.123",
                                "subnetId": "subnet-12345678",
                                "vpcId": "vpc-12345678",
                                "securityGroups": [{"groupId": "sg-12345678", "groupName": "default"}]
                            }
                        ]
                    }
                },
                "service": {
                    "serviceName": "guardduty",
                    "detectorId": "12345",
                    "action": {
                        "actionType": "PORT_PROBE",
                        "portProbeAction": {
                            "blocked": False,
                            "portProbeDetails": [
                                {
                                    "localPortDetails": {"port": 22, "portName": "SSH"},
                                    "remoteIpDetails": {
                                        "ipAddressV4": "198.51.100.123",
                                        "organization": {"orgName": "Test Org"},
                                        "country": {"countryName": "United States"},
                                        "city": {"cityName": "Seattle"}
                                    }
                                }
                            ]
                        }
                    },
                    "remoteIpDetails": {
                        "ipAddressV4": "198.51.100.123",
                        "organization": {"orgName": "Test Org"},
                        "country": {"countryName": "United States"},
                        "city": {"cityName": "Seattle"}
                    }
                },
                "severity": 6.0,
                "createdAt": "2024-01-15T12:30:45.456Z",
                "updatedAt": "2024-01-15T12:30:45.456Z",
                "title": "Unprotected port on EC2 instance i-1234567890abcdef0 is being probed.",
                "description": "EC2 instance has an unprotected port which is being probed by a known malicious host."
            }
        }
    
    @pytest.fixture
    def lambda_context(self):
        """Create a mock Lambda context."""
        context = Mock()
        context.aws_request_id = "test-request-id-123"
        context.function_name = "guardduty-vpc-enrichment-test"
        context.memory_limit_in_mb = 1024
        context.remaining_time_in_millis = lambda: 60000
        return context
    
    @patch('handler.sns_publisher.publish_alert')
    @patch('handler.flow_analyzer.analyze_flows')
    @patch('handler.guardduty_parser.parse_finding')
    @patch('handler.cloudwatch.put_metric_data')
    def test_lambda_handler_success_with_flow_logs(
        self, 
        mock_put_metric_data,
        mock_parse_finding,
        mock_analyze_flows,
        mock_publish_alert,
        sample_guardduty_event,
        lambda_context
    ):
        """Test successful Lambda handler execution with flow logs."""
        # Mock GuardDuty parser
        mock_finding = Mock()
        mock_finding.finding_id = "test-finding-id-12345"
        mock_finding.severity = 6.0
        mock_finding.finding_type = "Recon:EC2/PortProbeUnprotectedPort"
        mock_parse_finding.return_value = mock_finding
        
        # Mock flow logs analyzer
        mock_flow_analysis = {
            "logs_analyzed": 150,
            "traffic_summary": {"total_connections": 100},
            "suspicious_patterns": [{"pattern_type": "port_scanning"}]
        }
        mock_analyze_flows.return_value = mock_flow_analysis
        
        # Mock SNS publisher
        mock_publish_alert.return_value = {"MessageId": "test-message-id"}
        
        # Execute handler
        result = lambda_handler(sample_guardduty_event, lambda_context)
        
        # Verify result
        assert result["status"] == "success"
        assert result["correlation_id"] == "test-request-id-123"
        assert "finding_id" in result
        assert "processing_time_ms" in result
        assert "sns_message_id" in result
        
        # Verify method calls
        mock_parse_finding.assert_called_once_with(sample_guardduty_event)
        mock_analyze_flows.assert_called_once()
        mock_publish_alert.assert_called_once()
        mock_put_metric_data.assert_called()
    
    @patch('handler.sns_publisher.publish_alert')
    @patch('handler.flow_analyzer.analyze_flows')
    @patch('handler.guardduty_parser.parse_finding')
    def test_lambda_handler_success_without_flow_logs(
        self,
        mock_parse_finding,
        mock_analyze_flows,
        mock_publish_alert,
        sample_guardduty_event,
        lambda_context
    ):
        """Test successful Lambda handler execution without flow logs."""
        # Mock GuardDuty parser
        mock_finding = Mock()
        mock_finding.finding_id = "test-finding-id-12345"
        mock_finding.severity = 6.0
        mock_finding.finding_type = "Recon:EC2/PortProbeUnprotectedPort"
        mock_parse_finding.return_value = mock_finding
        
        # Mock flow logs analyzer returning None (no logs found)
        mock_analyze_flows.return_value = None
        
        # Mock SNS publisher
        mock_publish_alert.return_value = {"MessageId": "test-message-id"}
        
        # Execute handler
        result = lambda_handler(sample_guardduty_event, lambda_context)
        
        # Verify result
        assert result["status"] == "success"
        assert result["correlation_id"] == "test-request-id-123"
        
        # Verify flow analyzer was called but returned None
        mock_analyze_flows.assert_called_once()
        mock_publish_alert.assert_called_once()
    
    @patch('handler.guardduty_parser.parse_finding')
    def test_lambda_handler_below_severity_threshold(
        self,
        mock_parse_finding,
        sample_guardduty_event,
        lambda_context
    ):
        """Test Lambda handler with finding below severity threshold."""
        # Mock GuardDuty parser with low severity finding
        mock_finding = Mock()
        mock_finding.finding_id = "test-finding-id-12345"
        mock_finding.severity = 2.0  # Below threshold of 4.0
        mock_finding.finding_type = "Recon:EC2/PortProbeUnprotectedPort"
        mock_parse_finding.return_value = mock_finding
        
        # Execute handler
        result = lambda_handler(sample_guardduty_event, lambda_context)
        
        # Verify result
        assert result["status"] == "skipped"
        assert result["message"] == "Below severity threshold"
        assert result["correlation_id"] == "test-request-id-123"
    
    @patch('handler.guardduty_parser.parse_finding')
    def test_lambda_handler_validation_error(
        self,
        mock_parse_finding,
        sample_guardduty_event,
        lambda_context
    ):
        """Test Lambda handler with validation error."""
        # Mock GuardDuty parser raising ValueError
        mock_parse_finding.side_effect = ValueError("Invalid finding format")
        
        # Execute handler
        result = lambda_handler(sample_guardduty_event, lambda_context)
        
        # Verify result
        assert result["status"] == "error"
        assert "Validation error" in result["message"]
        assert result["correlation_id"] == "test-request-id-123"
    
    @patch('handler.sns_publisher.publish_alert')
    @patch('handler.flow_analyzer.analyze_flows')
    @patch('handler.guardduty_parser.parse_finding')
    def test_lambda_handler_aws_client_error(
        self,
        mock_parse_finding,
        mock_analyze_flows,
        mock_publish_alert,
        sample_guardduty_event,
        lambda_context
    ):
        """Test Lambda handler with AWS client error."""
        from botocore.exceptions import ClientError
        
        # Mock GuardDuty parser
        mock_finding = Mock()
        mock_finding.finding_id = "test-finding-id-12345"
        mock_finding.severity = 6.0
        mock_finding.finding_type = "Recon:EC2/PortProbeUnprotectedPort"
        mock_parse_finding.return_value = mock_finding
        
        # Mock flow analyzer raising ClientError
        mock_analyze_flows.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            'GetObject'
        )
        
        # Execute handler
        result = lambda_handler(sample_guardduty_event, lambda_context)
        
        # Verify result
        assert result["status"] == "error"
        assert "AWS service error: AccessDenied" in result["message"]
        assert result["correlation_id"] == "test-request-id-123"
    
    @patch('handler.sns_publisher.publish_alert')
    @patch('handler.flow_analyzer.analyze_flows')
    @patch('handler.guardduty_parser.parse_finding')
    def test_lambda_handler_unexpected_error(
        self,
        mock_parse_finding,
        mock_analyze_flows,
        mock_publish_alert,
        sample_guardduty_event,
        lambda_context
    ):
        """Test Lambda handler with unexpected error."""
        # Mock GuardDuty parser
        mock_finding = Mock()
        mock_finding.finding_id = "test-finding-id-12345"
        mock_finding.severity = 6.0
        mock_finding.finding_type = "Recon:EC2/PortProbeUnprotectedPort"
        mock_parse_finding.return_value = mock_finding
        
        # Mock flow analyzer raising unexpected exception
        mock_analyze_flows.side_effect = RuntimeError("Unexpected runtime error")
        
        # Execute handler
        result = lambda_handler(sample_guardduty_event, lambda_context)
        
        # Verify result
        assert result["status"] == "error"
        assert "Unexpected error" in result["message"]
        assert result["correlation_id"] == "test-request-id-123"
    
    @patch('handler.cloudwatch.put_metric_data')
    def test_send_metrics_success(self, mock_put_metric_data):
        """Test successful metrics sending."""
        from handler import _send_metrics
        
        _send_metrics(
            processing_time=1500,
            finding_severity=6.0,
            logs_analyzed=150,
            patterns_detected=2
        )
        
        mock_put_metric_data.assert_called_once()
        call_args = mock_put_metric_data.call_args[1]
        assert call_args['Namespace'] == 'GuardDuty/Enrichment'
        assert len(call_args['MetricData']) == 5  # 5 metrics
        
        # Verify metric names
        metric_names = [metric['MetricName'] for metric in call_args['MetricData']]
        expected_metrics = [
            'ProcessingDuration',
            'FindingSeverity', 
            'FlowLogsAnalyzed',
            'SuspiciousPatternsDetected',
            'EnrichmentSuccess'
        ]
        for expected in expected_metrics:
            assert expected in metric_names
    
    @patch('handler.cloudwatch.put_metric_data')
    def test_send_error_metric(self, mock_put_metric_data):
        """Test error metric sending."""
        from handler import _send_error_metric
        
        _send_error_metric("validation_error")
        
        mock_put_metric_data.assert_called_once()
        call_args = mock_put_metric_data.call_args[1]
        assert call_args['Namespace'] == 'GuardDuty/Enrichment'
        
        metric_data = call_args['MetricData'][0]
        assert metric_data['MetricName'] == 'EnrichmentFailure'
        assert metric_data['Value'] == 1
        assert metric_data['Dimensions'][0]['Value'] == 'validation_error'
    
    def test_create_response(self):
        """Test response creation utility function."""
        from handler import _create_response
        
        response = _create_response(
            status="success",
            message="Test message",
            correlation_id="test-id",
            additional_data={"key": "value"}
        )
        
        assert response["status"] == "success"
        assert response["message"] == "Test message"
        assert response["correlation_id"] == "test-id"
        assert response["key"] == "value"
        assert "timestamp" in response
    
    @patch('handler.sns_publisher.publish_alert')
    @patch('handler.flow_analyzer.analyze_flows')
    @patch('handler.guardduty_parser.parse_finding')
    @patch('handler.enrichment_engine.enrich_finding')
    def test_lambda_handler_full_flow_integration(
        self,
        mock_enrich_finding,
        mock_parse_finding,
        mock_analyze_flows,
        mock_publish_alert,
        sample_guardduty_event,
        lambda_context
    ):
        """Test full integration flow of the Lambda handler."""
        # Mock GuardDuty parser
        mock_finding = Mock()
        mock_finding.finding_id = "test-finding-id-12345"
        mock_finding.severity = 6.0
        mock_finding.finding_type = "Recon:EC2/PortProbeUnprotectedPort"
        mock_parse_finding.return_value = mock_finding
        
        # Mock flow logs analyzer
        mock_flow_analysis = {
            "logs_analyzed": 150,
            "traffic_summary": {"total_connections": 100},
            "suspicious_patterns": [{"pattern_type": "port_scanning"}]
        }
        mock_analyze_flows.return_value = mock_flow_analysis
        
        # Mock enrichment engine
        mock_enriched_alert = {
            "finding_id": "test-finding-id-12345",
            "severity": 6.0,
            "network_context": {
                "suspicious_patterns": [{"pattern_type": "port_scanning"}]
            }
        }
        mock_enrich_finding.return_value = mock_enriched_alert
        
        # Mock SNS publisher
        mock_publish_alert.return_value = {"MessageId": "test-message-id"}
        
        # Execute handler
        result = lambda_handler(sample_guardduty_event, lambda_context)
        
        # Verify all components were called in sequence
        mock_parse_finding.assert_called_once_with(sample_guardduty_event)
        mock_analyze_flows.assert_called_once_with(
            finding_data=mock_finding,
            correlation_id="test-request-id-123"
        )
        mock_enrich_finding.assert_called_once_with(
            finding_data=mock_finding,
            flow_analysis=mock_flow_analysis,
            correlation_id="test-request-id-123"
        )
        mock_publish_alert.assert_called_once_with(
            enriched_alert=mock_enriched_alert,
            correlation_id="test-request-id-123"
        )
        
        # Verify successful result
        assert result["status"] == "success"
        assert result["finding_id"] == "test-finding-id-12345"
        assert result["sns_message_id"] == "test-message-id"
    
    def test_lambda_handler_invalid_event_structure(self, lambda_context):
        """Test Lambda handler with invalid event structure."""
        invalid_event = {
            "version": "0",
            "id": "12345678-1234-1234-1234-123456789012",
            "source": "aws.ec2",  # Wrong source
            "detail": {}
        }
        
        result = lambda_handler(invalid_event, lambda_context)
        
        assert result["status"] == "error"
        assert "Validation error" in result["message"]
    
    @patch('handler.cloudwatch.put_metric_data')
    def test_metrics_sending_failure_handling(self, mock_put_metric_data):
        """Test handling of metrics sending failures."""
        from handler import _send_metrics
        
        # Mock CloudWatch to raise exception
        mock_put_metric_data.side_effect = Exception("CloudWatch error")
        
        # Should not raise exception, just log warning
        _send_metrics(1500, 6.0, 150, 2)
        
        mock_put_metric_data.assert_called_once()
    
    @patch.dict(os.environ, {'SEVERITY_THRESHOLD': '6.0'})
    @patch('handler.guardduty_parser.parse_finding')
    def test_lambda_handler_custom_severity_threshold(
        self,
        mock_parse_finding,
        sample_guardduty_event,
        lambda_context
    ):
        """Test Lambda handler with custom severity threshold."""
        # Mock GuardDuty parser with finding at threshold
        mock_finding = Mock()
        mock_finding.finding_id = "test-finding-id-12345"
        mock_finding.severity = 5.0  # Below custom threshold of 6.0
        mock_finding.finding_type = "Recon:EC2/PortProbeUnprotectedPort"
        mock_parse_finding.return_value = mock_finding
        
        # Execute handler
        result = lambda_handler(sample_guardduty_event, lambda_context)
        
        # Should be skipped due to severity threshold
        assert result["status"] == "skipped"
        assert "Below severity threshold" in result["message"]