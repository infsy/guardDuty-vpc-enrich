import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
import json
import sys
import os

# Add lambda directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'lambda'))

from sns_publisher import SNSPublisher


class TestSNSPublisher:
    
    def setup_method(self):
        with patch.dict(os.environ, {'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-topic'}):
            self.publisher = SNSPublisher()
    
    @pytest.fixture
    def sample_enriched_alert(self):
        """Create a sample enriched alert for testing."""
        return {
            "finding_id": "test-finding-123",
            "severity": 6.0,
            "finding_type": "Recon:EC2/PortProbeUnprotectedPort",
            "timestamp": "2024-01-15T12:30:45",
            "title": "Unprotected port on EC2 instance",
            "description": "EC2 instance has an unprotected port which is being probed by a known malicious host. This is a longer description that might need to be truncated in some contexts to fit within message size limits.",
            "region": "us-east-1",
            "account_id": "123456789012",
            "resource": {
                "instance_id": "i-1234567890abcdef0",
                "resource_type": "Instance",
                "network_interfaces": [
                    {
                        "interface_id": "eni-12345678",
                        "private_ip": "10.0.1.100",
                        "public_ip": "203.0.113.123",
                        "vpc_id": "vpc-12345678",
                        "subnet_id": "subnet-12345678",
                        "security_groups": ["sg-12345678"]
                    }
                ]
            },
            "network_context": {
                "time_window": {
                    "start": "2024-01-15T12:15:45",
                    "end": "2024-01-15T12:45:45"
                },
                "traffic_summary": {
                    "total_connections": 100,
                    "unique_remote_ips": 5,
                    "total_bytes_in": 10000,
                    "total_bytes_out": 50000,
                    "rejected_connections": 20,
                    "unique_ports": [22, 80, 443],
                    "protocol_distribution": {6: 90, 17: 10}
                },
                "top_talkers": [
                    {
                        "ip": "198.51.100.200",
                        "direction": "inbound",
                        "bytes": 25000,
                        "packets": 500,
                        "ports": [22, 80],
                        "connections": 50
                    }
                ],
                "suspicious_patterns": [
                    {
                        "pattern_type": "port_scanning",
                        "description": "Port scanning detected from 198.51.100.200",
                        "severity_assessment": {"level": "high"},
                        "evidence": {"source_ip": "198.51.100.200", "unique_ports": 15}
                    },
                    {
                        "pattern_type": "repeated_rejections",
                        "description": "High rejection rate",
                        "severity_assessment": {"level": "medium"},
                        "evidence": {"rejected_connections": 50}
                    }
                ]
            },
            "correlation_insights": {
                "correlation_quality": "high",
                "flow_logs_availability": "available",
                "threat_validation": {"validation_status": "confirmed"}
            },
            "security_recommendations": [
                {
                    "priority": "critical",
                    "action": "Isolate affected instance",
                    "category": "immediate_action",
                    "description": "Immediately isolate the instance"
                },
                {
                    "priority": "high",
                    "action": "Review firewall rules",
                    "category": "network_security",
                    "description": "Review and update firewall rules"
                },
                {
                    "priority": "medium",
                    "action": "Monitor for similar patterns",
                    "category": "monitoring",
                    "description": "Set up monitoring"
                }
            ],
            "analysis_metadata": {
                "processing_time_ms": 1500,
                "logs_analyzed": 150,
                "correlation_id": "test-correlation-id",
                "timestamp": "2024-01-15T12:30:50"
            }
        }
    
    def test_init_success(self):
        """Test successful initialization."""
        with patch.dict(os.environ, {'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-topic'}):
            publisher = SNSPublisher()
            assert publisher.topic_arn == 'arn:aws:sns:us-east-1:123456789012:test-topic'
            assert publisher.max_retries == 3
            assert publisher.retry_delay == 1
    
    def test_init_missing_topic_arn(self):
        """Test initialization fails without topic ARN."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="SNS_TOPIC_ARN environment variable not set"):
                SNSPublisher()
    
    @patch('sns_publisher.boto3.client')
    def test_publish_alert_success(self, mock_boto3, sample_enriched_alert):
        """Test successful alert publishing."""
        mock_sns = Mock()
        mock_boto3.return_value = mock_sns
        mock_sns.publish.return_value = {'MessageId': 'test-message-id-123'}
        
        result = self.publisher.publish_alert(sample_enriched_alert, "test-correlation-id")
        
        assert result['MessageId'] == 'test-message-id-123'
        mock_sns.publish.assert_called_once()
        
        # Verify call arguments
        call_args = mock_sns.publish.call_args[1]
        assert call_args['TopicArn'] == self.publisher.topic_arn
        assert 'Message' in call_args
        assert 'Subject' in call_args
        assert 'MessageAttributes' in call_args
    
    def test_create_subject_critical_severity(self, sample_enriched_alert):
        """Test subject creation for critical severity alert."""
        sample_enriched_alert['severity'] = 8.0
        
        subject = self.publisher._create_subject(sample_enriched_alert)
        
        assert subject.startswith("[CRITICAL]")
        assert "ENRICHED" in subject  # Has flow logs
        assert "123456789012" in subject
        assert len(subject) <= 100  # SNS limit
    
    def test_create_subject_no_flow_logs(self, sample_enriched_alert):
        """Test subject creation without flow logs."""
        # Remove network context to simulate no flow logs
        del sample_enriched_alert['network_context']
        
        subject = self.publisher._create_subject(sample_enriched_alert)
        
        assert "BASIC" in subject  # No flow logs enrichment
        assert "[HIGH]" in subject  # Severity 6.0
    
    def test_create_subject_long_truncation(self, sample_enriched_alert):
        """Test subject truncation for very long finding types."""
        sample_enriched_alert['finding_type'] = "VeryLongFindingTypeNameThatExceedsNormalLimitsAndShouldBeTruncated:EC2/SomeSpecificThreatPattern"
        
        subject = self.publisher._create_subject(sample_enriched_alert)
        
        assert len(subject) <= 100
        assert subject.endswith("...")
    
    def test_create_compact_alert(self, sample_enriched_alert):
        """Test compact alert creation."""
        compact_alert = self.publisher._create_compact_alert(sample_enriched_alert)
        
        # Check core fields are present
        assert compact_alert['finding_id'] == "test-finding-123"
        assert compact_alert['severity'] == 6.0
        assert compact_alert['finding_type'] == "Recon:EC2/PortProbeUnprotectedPort"
        
        # Check network summary
        assert compact_alert['network_summary']['has_flow_logs'] is True
        assert compact_alert['network_summary']['traffic_summary'] == sample_enriched_alert['network_context']['traffic_summary']
        
        # Check key patterns (should be limited to top 3)
        assert len(compact_alert['key_patterns']) == 2  # We have 2 patterns in test data
        assert compact_alert['key_patterns'][0]['type'] == 'port_scanning'
        
        # Check correlation summary
        assert compact_alert['correlation_summary']['quality'] == 'high'
        
        # Check priority recommendations (should be high/critical priority only)
        assert len(compact_alert['priority_recommendations']) == 2  # critical + high priority
        assert compact_alert['priority_recommendations'][0]['priority'] == 'critical'
        
        # Check analysis info
        assert compact_alert['analysis_info']['processing_time_ms'] == 1500
        assert compact_alert['analysis_info']['logs_analyzed'] == 150
    
    def test_create_compact_alert_no_network_context(self, sample_enriched_alert):
        """Test compact alert creation without network context."""
        del sample_enriched_alert['network_context']
        
        compact_alert = self.publisher._create_compact_alert(sample_enriched_alert)
        
        assert compact_alert['network_summary']['has_flow_logs'] is False
        assert 'reason' in compact_alert['network_summary']
        assert 'key_patterns' not in compact_alert
    
    def test_create_compact_alert_long_description(self, sample_enriched_alert):
        """Test compact alert with very long description."""
        long_description = "A" * 600  # Longer than 500 char limit
        sample_enriched_alert['description'] = long_description
        
        compact_alert = self.publisher._create_compact_alert(sample_enriched_alert)
        
        assert len(compact_alert['description']) <= 503  # 500 + "..."
        assert compact_alert['description'].endswith('...')
    
    def test_prepare_message(self, sample_enriched_alert):
        """Test message preparation with attributes."""
        message_data = self.publisher._prepare_message(sample_enriched_alert, "test-correlation-id")
        
        # Check message structure
        assert message_data['TopicArn'] == self.publisher.topic_arn
        assert 'Message' in message_data
        assert 'Subject' in message_data
        assert 'MessageAttributes' in message_data
        
        # Check message attributes
        attrs = message_data['MessageAttributes']
        assert attrs['finding_type']['StringValue'] == "Recon:EC2/PortProbeUnprotectedPort"
        assert attrs['severity']['StringValue'] == "6.0"
        assert attrs['account_id']['StringValue'] == "123456789012"
        assert attrs['region']['StringValue'] == "us-east-1"
        assert attrs['correlation_id']['StringValue'] == "test-correlation-id"
        assert attrs['alert_source']['StringValue'] == "guardduty-vpc-enrichment"
        assert attrs['has_flow_logs']['StringValue'] == "true"
        assert attrs['suspicious_patterns_count']['StringValue'] == "2"
        assert attrs['total_connections']['StringValue'] == "100"
        
        # Check message is valid JSON
        message_obj = json.loads(message_data['Message'])
        assert message_obj['finding_id'] == "test-finding-123"
    
    def test_prepare_message_no_flow_logs(self, sample_enriched_alert):
        """Test message preparation without flow logs."""
        del sample_enriched_alert['network_context']
        
        message_data = self.publisher._prepare_message(sample_enriched_alert, "test-correlation-id")
        
        attrs = message_data['MessageAttributes']
        assert attrs['has_flow_logs']['StringValue'] == "false"
        assert 'suspicious_patterns_count' not in attrs
        assert 'total_connections' not in attrs
    
    @patch('sns_publisher.boto3.client')
    def test_publish_with_retry_success_first_attempt(self, mock_boto3):
        """Test successful publish on first attempt."""
        mock_sns = Mock()
        mock_boto3.return_value = mock_sns
        mock_sns.publish.return_value = {'MessageId': 'test-message-id'}
        
        message_data = {
            'TopicArn': 'test-topic',
            'Message': 'test message',
            'Subject': 'test subject'
        }
        
        result = self.publisher._publish_with_retry(message_data, "test-correlation-id")
        
        assert result['MessageId'] == 'test-message-id'
        assert mock_sns.publish.call_count == 1
    
    @patch('sns_publisher.boto3.client')
    @patch('sns_publisher.time.sleep')
    def test_publish_with_retry_success_after_retries(self, mock_sleep, mock_boto3):
        """Test successful publish after retries."""
        mock_sns = Mock()
        mock_boto3.return_value = mock_sns
        
        # Fail first two attempts, succeed on third
        mock_sns.publish.side_effect = [
            ClientError({'Error': {'Code': 'Throttling'}}, 'Publish'),
            ClientError({'Error': {'Code': 'ServiceUnavailable'}}, 'Publish'),
            {'MessageId': 'test-message-id'}
        ]
        
        message_data = {
            'TopicArn': 'test-topic',
            'Message': 'test message',
            'Subject': 'test subject'
        }
        
        result = self.publisher._publish_with_retry(message_data, "test-correlation-id")
        
        assert result['MessageId'] == 'test-message-id'
        assert mock_sns.publish.call_count == 3
        assert mock_sleep.call_count == 2  # Should sleep before retries
    
    @patch('sns_publisher.boto3.client')
    def test_publish_with_retry_non_retryable_error(self, mock_boto3):
        """Test publish with non-retryable error."""
        mock_sns = Mock()
        mock_boto3.return_value = mock_sns
        mock_sns.publish.side_effect = ClientError({'Error': {'Code': 'InvalidParameter'}}, 'Publish')
        
        message_data = {
            'TopicArn': 'test-topic',
            'Message': 'test message',
            'Subject': 'test subject'
        }
        
        with pytest.raises(ClientError):
            self.publisher._publish_with_retry(message_data, "test-correlation-id")
        
        assert mock_sns.publish.call_count == 1  # Should not retry
    
    @patch('sns_publisher.boto3.client')
    @patch('sns_publisher.time.sleep')
    def test_publish_with_retry_all_attempts_fail(self, mock_sleep, mock_boto3):
        """Test publish when all retry attempts fail."""
        mock_sns = Mock()
        mock_boto3.return_value = mock_sns
        mock_sns.publish.side_effect = ClientError({'Error': {'Code': 'Throttling'}}, 'Publish')
        
        message_data = {
            'TopicArn': 'test-topic',
            'Message': 'test message',
            'Subject': 'test subject'
        }
        
        with pytest.raises(ClientError):
            self.publisher._publish_with_retry(message_data, "test-correlation-id")
        
        assert mock_sns.publish.call_count == 3  # All retry attempts
        assert mock_sleep.call_count == 2  # Sleep before retries 2 and 3
    
    @patch('sns_publisher.boto3.client')
    def test_validate_topic_access_success(self, mock_boto3):
        """Test successful topic access validation."""
        mock_sns = Mock()
        mock_boto3.return_value = mock_sns
        mock_sns.get_topic_attributes.return_value = {'Attributes': {}}
        
        result = self.publisher.validate_topic_access()
        
        assert result is True
        mock_sns.get_topic_attributes.assert_called_once_with(TopicArn=self.publisher.topic_arn)
    
    @patch('sns_publisher.boto3.client')
    def test_validate_topic_access_failure(self, mock_boto3):
        """Test topic access validation failure."""
        mock_sns = Mock()
        mock_boto3.return_value = mock_sns
        mock_sns.get_topic_attributes.side_effect = ClientError({'Error': {'Code': 'NotFound'}}, 'GetTopicAttributes')
        
        result = self.publisher.validate_topic_access()
        
        assert result is False
    
    @patch('sns_publisher.boto3.client')
    def test_publish_test_message_success(self, mock_boto3):
        """Test successful test message publishing."""
        mock_sns = Mock()
        mock_boto3.return_value = mock_sns
        mock_sns.publish.return_value = {'MessageId': 'test-message-id'}
        
        result = self.publisher.publish_test_message("test-correlation-id")
        
        assert result is True
        mock_sns.publish.assert_called_once()
        
        # Verify test message structure
        call_args = mock_sns.publish.call_args[1]
        assert '[TEST]' in call_args['Subject']
        message = json.loads(call_args['Message'])
        assert message['test_message'] is True
        assert message['correlation_id'] == "test-correlation-id"
    
    @patch('sns_publisher.boto3.client')
    def test_publish_test_message_failure(self, mock_boto3):
        """Test test message publishing failure."""
        mock_sns = Mock()
        mock_boto3.return_value = mock_sns
        mock_sns.publish.side_effect = ClientError({'Error': {'Code': 'Throttling'}}, 'Publish')
        
        result = self.publisher.publish_test_message("test-correlation-id")
        
        assert result is False
    
    @patch('sns_publisher.boto3.client')
    def test_publish_alert_exception_handling(self, mock_boto3, sample_enriched_alert):
        """Test exception handling in publish_alert method."""
        mock_sns = Mock()
        mock_boto3.return_value = mock_sns
        mock_sns.publish.side_effect = Exception("Unexpected error")
        
        with pytest.raises(Exception, match="Unexpected error"):
            self.publisher.publish_alert(sample_enriched_alert, "test-correlation-id")
    
    def test_severity_levels_in_subject(self, sample_enriched_alert):
        """Test different severity levels in subject creation."""
        # Test LOW severity
        sample_enriched_alert['severity'] = 1.0
        subject = self.publisher._create_subject(sample_enriched_alert)
        assert "[LOW]" in subject
        
        # Test MEDIUM severity
        sample_enriched_alert['severity'] = 4.0
        subject = self.publisher._create_subject(sample_enriched_alert)
        assert "[MEDIUM]" in subject
        
        # Test HIGH severity
        sample_enriched_alert['severity'] = 6.0
        subject = self.publisher._create_subject(sample_enriched_alert)
        assert "[HIGH]" in subject
        
        # Test CRITICAL severity
        sample_enriched_alert['severity'] = 8.0
        subject = self.publisher._create_subject(sample_enriched_alert)
        assert "[CRITICAL]" in subject