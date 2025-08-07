import pytest
from unittest.mock import patch, Mock
from datetime import datetime
import sys
import os

# Add lambda directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'lambda'))

from enrichment_engine import EnrichmentEngine
from guardduty_parser import GuardDutyFinding, NetworkInterface, RemoteIPDetails, PortDetails


class TestEnrichmentEngine:
    
    def setup_method(self):
        self.engine = EnrichmentEngine()
    
    @pytest.fixture
    def sample_finding(self):
        """Create a sample GuardDuty finding for testing."""
        return GuardDutyFinding(
            finding_id="test-finding-123",
            severity=6.0,
            finding_type="Recon:EC2/PortProbeUnprotectedPort",
            timestamp=datetime(2024, 1, 15, 12, 30, 45),
            title="Unprotected port on EC2 instance",
            description="EC2 instance has an unprotected port which is being probed",
            region="us-east-1",
            account_id="123456789012",
            instance_id="i-1234567890abcdef0",
            resource_type="Instance",
            network_interfaces=[
                NetworkInterface(
                    interface_id="eni-12345678",
                    private_ip="10.0.1.100",
                    public_ip="203.0.113.123",
                    vpc_id="vpc-12345678",
                    subnet_id="subnet-12345678",
                    security_groups=["sg-12345678"]
                )
            ],
            remote_ip_details=[
                RemoteIPDetails(
                    ip_address="198.51.100.123",
                    country="United States",
                    city="Seattle",
                    organization="Amazon.com",
                    is_malicious=True
                )
            ],
            port_details=[
                PortDetails(port=22, port_name="SSH")
            ],
            raw_finding={}
        )
    
    @pytest.fixture
    def sample_flow_analysis(self):
        """Create sample flow analysis data."""
        return {
            "time_window": {
                "start": "2024-01-15T12:15:45",
                "end": "2024-01-15T12:45:45"
            },
            "target_ips": ["10.0.1.100", "203.0.113.123", "198.51.100.123"],
            "target_ports": [22, 80],
            "logs_analyzed": 150,
            "traffic_summary": {
                "total_connections": 100,
                "unique_remote_ips": 5,
                "total_bytes_in": 10000,
                "total_bytes_out": 50000,
                "rejected_connections": 20,
                "unique_ports": [22, 80, 443, 8080],
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
                    "evidence": {
                        "source_ip": "198.51.100.200",
                        "unique_ports": 15,
                        "ports_accessed": [22, 23, 80, 443, 8080]
                    }
                }
            ],
            "raw_flow_logs": [
                {
                    "srcaddr": "10.0.1.100",
                    "dstaddr": "198.51.100.123",
                    "srcport": 12345,
                    "dstport": 22,
                    "protocol": 6,
                    "bytes": 1500,
                    "action": "ACCEPT"
                }
            ]
        }
    
    def test_enrich_finding_with_flow_analysis(self, sample_finding, sample_flow_analysis):
        """Test enriching finding with flow analysis data."""
        result = self.engine.enrich_finding(sample_finding, sample_flow_analysis, "test-correlation-id")
        
        # Check base alert structure
        assert result["finding_id"] == "test-finding-123"
        assert result["severity"] == 6.0
        assert result["finding_type"] == "Recon:EC2/PortProbeUnprotectedPort"
        assert result["account_id"] == "123456789012"
        assert result["region"] == "us-east-1"
        
        # Check resource information
        assert result["resource"]["instance_id"] == "i-1234567890abcdef0"
        assert len(result["resource"]["network_interfaces"]) == 1
        assert result["resource"]["network_interfaces"][0]["private_ip"] == "10.0.1.100"
        
        # Check threat intelligence
        assert len(result["threat_intelligence"]["remote_ips"]) == 1
        assert result["threat_intelligence"]["remote_ips"][0]["ip_address"] == "198.51.100.123"
        assert result["threat_intelligence"]["remote_ips"][0]["is_malicious"] is True
        
        # Check network context
        assert result["network_context"] is not None
        assert result["network_context"]["traffic_summary"]["total_connections"] == 100
        assert len(result["network_context"]["top_talkers"]) == 1
        assert len(result["network_context"]["suspicious_patterns"]) >= 1  # Original + enhanced
        
        # Check correlation insights
        assert result["correlation_insights"] is not None
        assert result["correlation_insights"]["flow_logs_availability"] == "available"
        
        # Check security recommendations
        assert "security_recommendations" in result
        assert len(result["security_recommendations"]) > 0
        
        # Check analysis metadata
        assert result["analysis_metadata"] is not None
        assert result["analysis_metadata"]["logs_analyzed"] == 150
    
    def test_enrich_finding_without_flow_analysis(self, sample_finding):
        """Test enriching finding without flow analysis data."""
        result = self.engine.enrich_finding(sample_finding, None, "test-correlation-id")
        
        # Check base alert structure is still present
        assert result["finding_id"] == "test-finding-123"
        assert result["severity"] == 6.0
        
        # Check empty network context
        assert result["network_context"]["traffic_summary"]["total_connections"] == 0
        assert result["network_context"]["top_talkers"] == []
        assert result["network_context"]["suspicious_patterns"] == []
        
        # Check correlation insights show no flow logs
        assert result["correlation_insights"]["flow_logs_availability"] == "no_matching_logs"
        assert "analysis_limitation" in result["correlation_insights"]
    
    def test_create_base_alert(self, sample_finding):
        """Test base alert creation."""
        base_alert = self.engine._create_base_alert(sample_finding)
        
        assert base_alert["finding_id"] == "test-finding-123"
        assert base_alert["severity"] == 6.0
        assert base_alert["finding_type"] == "Recon:EC2/PortProbeUnprotectedPort"
        assert base_alert["title"] == "Unprotected port on EC2 instance"
        assert base_alert["description"] == "EC2 instance has an unprotected port which is being probed"
        assert base_alert["region"] == "us-east-1"
        assert base_alert["account_id"] == "123456789012"
        
        # Check resource details
        assert base_alert["resource"]["instance_id"] == "i-1234567890abcdef0"
        assert base_alert["resource"]["resource_type"] == "Instance"
        assert len(base_alert["resource"]["network_interfaces"]) == 1
        
        # Check threat intelligence
        assert len(base_alert["threat_intelligence"]["remote_ips"]) == 1
        assert len(base_alert["threat_intelligence"]["ports_involved"]) == 1
    
    def test_assess_pattern_severity_high_guardduty(self, sample_finding):
        """Test pattern severity assessment with high GuardDuty severity."""
        sample_finding.severity = 8.0  # High severity
        
        pattern = {
            "pattern_type": "port_scanning",
            "evidence": {"unique_ports": 15}
        }
        
        assessment = self.engine._assess_pattern_severity(pattern, sample_finding)
        
        assert assessment["level"] == "high"
        assert "high_guardduty_severity" in assessment["factors"]
        assert assessment["confidence"] in ["low", "medium", "high"]
    
    def test_assess_pattern_severity_cryptocurrency(self, sample_finding):
        """Test pattern severity assessment with cryptocurrency finding."""
        sample_finding.finding_type = "CryptoCurrency:EC2/BitcoinTool.B!DNS"
        sample_finding.severity = 8.0
        
        pattern = {
            "pattern_type": "data_exfiltration",
            "evidence": {"bytes_transferred": 150000000}
        }
        
        assessment = self.engine._assess_pattern_severity(pattern, sample_finding)
        
        assert assessment["level"] == "critical"
        assert any("high_risk_finding_type" in factor for factor in assessment["factors"])
    
    def test_assess_pattern_severity_malicious_ip(self, sample_finding):
        """Test pattern severity assessment with known malicious IP."""
        pattern = {
            "pattern_type": "repeated_rejections",
            "evidence": {"rejected_connections": 100}
        }
        
        assessment = self.engine._assess_pattern_severity(pattern, sample_finding)
        
        assert assessment["level"] == "high"  # Should be elevated due to malicious IP
        assert "known_malicious_ip" in assessment["factors"]
    
    def test_correlate_with_guardduty_port_scanning(self, sample_finding):
        """Test correlation with GuardDuty for port scanning pattern."""
        pattern = {
            "pattern_type": "port_scanning",
            "evidence": {"unique_ports": 15}
        }
        
        correlation = self.engine._correlate_with_guardduty(pattern, sample_finding)
        
        assert correlation["finding_type_relevance"] == "high"  # Recon finding
        assert correlation["asset_correlation"] == "confirmed"
        assert correlation["threat_correlation"] == "confirmed_malicious"
    
    def test_correlate_with_guardduty_data_exfiltration(self, sample_finding):
        """Test correlation with GuardDuty for data exfiltration pattern."""
        sample_finding.finding_type = "Exfiltration:S3/ObjectRead.Unusual"
        
        pattern = {
            "pattern_type": "data_exfiltration",
            "evidence": {"bytes_transferred": 150000000}
        }
        
        correlation = self.engine._correlate_with_guardduty(pattern, sample_finding)
        
        assert correlation["finding_type_relevance"] == "high"  # Exfiltration finding
    
    def test_generate_guardduty_specific_patterns_cryptocurrency(self, sample_finding):
        """Test GuardDuty-specific pattern generation for cryptocurrency."""
        sample_finding.finding_type = "CryptoCurrency:EC2/BitcoinTool.B!DNS"
        
        patterns = self.engine._generate_guardduty_specific_patterns(sample_finding)
        
        assert len(patterns) == 1
        assert patterns[0]["pattern_type"] == "cryptocurrency_mining"
        assert patterns[0]["severity_assessment"]["level"] == "high"
    
    def test_generate_guardduty_specific_patterns_backdoor(self, sample_finding):
        """Test GuardDuty-specific pattern generation for backdoor."""
        sample_finding.finding_type = "Backdoor:EC2/C&CActivity.B!DNS"
        
        patterns = self.engine._generate_guardduty_specific_patterns(sample_finding)
        
        assert len(patterns) == 1
        assert patterns[0]["pattern_type"] == "backdoor_communication"
        assert patterns[0]["severity_assessment"]["level"] == "critical"
    
    def test_generate_correlation_insights_high_quality(self, sample_finding, sample_flow_analysis):
        """Test correlation insights generation with high quality data."""
        insights = self.engine._generate_correlation_insights(sample_finding, sample_flow_analysis)
        
        assert insights["flow_logs_availability"] == "available"
        assert insights["correlation_quality"] == "high"
        assert insights["timeline_analysis"]["temporal_correlation"] == "within_analysis_window"
        assert insights["network_behavior_analysis"]["activity_level"] == "medium"
        assert insights["threat_validation"]["validation_status"] == "confirmed"
    
    def test_assess_activity_level(self):
        """Test network activity level assessment."""
        # High activity
        high_traffic = {"total_connections": 2000, "total_bytes_in": 150000000, "total_bytes_out": 0}
        assert self.engine._assess_activity_level(high_traffic) == "high"
        
        # Medium activity
        medium_traffic = {"total_connections": 500, "total_bytes_in": 15000000, "total_bytes_out": 0}
        assert self.engine._assess_activity_level(medium_traffic) == "medium"
        
        # Low activity
        low_traffic = {"total_connections": 50, "total_bytes_in": 1000000, "total_bytes_out": 0}
        assert self.engine._assess_activity_level(low_traffic) == "low"
    
    def test_analyze_communication_patterns(self):
        """Test communication patterns analysis."""
        traffic_summary = {
            "unique_remote_ips": 10,
            "total_connections": 100,
            "rejected_connections": 25,
            "protocol_distribution": {6: 80, 17: 20},
            "unique_ports": [22, 80, 443, 8080, 3389]
        }
        
        patterns = self.engine._analyze_communication_patterns(traffic_summary)
        
        assert patterns["unique_remote_ips"] == 10
        assert patterns["rejected_connection_ratio"] == 0.25
        assert patterns["protocol_diversity"] == 2
        assert patterns["port_diversity"] == 5
    
    def test_assess_security_implications(self, sample_finding):
        """Test security implications assessment."""
        traffic_summary = {
            "rejected_connections": 75,  # High rejection rate
            "total_bytes_out": 150000000,  # > 100MB outbound
            "unique_remote_ips": 100,  # Many unique IPs
            "protocol_distribution": {6: 50, 17: 30, 1: 20, 47: 10, 50: 5, 89: 5}  # Many protocols
        }
        
        implications = self.engine._assess_security_implications(traffic_summary, sample_finding)
        
        assert "high_rejection_rate_indicates_blocked_attacks" in implications
        assert "large_outbound_transfer_potential_exfiltration" in implications
        assert "communication_with_many_ips_potential_scanning" in implications
        assert "multiple_protocols_used_unusual_behavior" in implications
    
    def test_get_guardduty_recommendations_cryptocurrency(self, sample_finding):
        """Test GuardDuty-specific recommendations for cryptocurrency."""
        sample_finding.finding_type = "CryptoCurrency:EC2/BitcoinTool.B!DNS"
        
        recommendations = self.engine._get_guardduty_recommendations(sample_finding)
        
        crypto_rec = next((r for r in recommendations if "cryptocurrency" in r["action"].lower()), None)
        assert crypto_rec is not None
        assert crypto_rec["priority"] == "high"
        assert crypto_rec["category"] == "immediate_action"
    
    def test_get_guardduty_recommendations_backdoor(self, sample_finding):
        """Test GuardDuty-specific recommendations for backdoor."""
        sample_finding.finding_type = "Backdoor:EC2/C&CActivity.B!DNS"
        
        recommendations = self.engine._get_guardduty_recommendations(sample_finding)
        
        backdoor_rec = next((r for r in recommendations if "isolate" in r["action"].lower()), None)
        assert backdoor_rec is not None
        assert backdoor_rec["priority"] == "critical"
    
    def test_get_flow_analysis_recommendations(self, sample_finding, sample_flow_analysis):
        """Test flow analysis-specific recommendations."""
        recommendations = self.engine._get_flow_analysis_recommendations(sample_flow_analysis, sample_finding)
        
        # Should have recommendation for port scanning pattern
        port_scan_rec = next((r for r in recommendations if "port scanning" in r["description"]), None)
        assert port_scan_rec is not None
        assert port_scan_rec["category"] == "network_security"
    
    def test_get_general_recommendations(self, sample_finding):
        """Test general security recommendations."""
        recommendations = self.engine._get_general_recommendations(sample_finding)
        
        assert len(recommendations) >= 3
        
        # Check for expected recommendation categories
        categories = [r["category"] for r in recommendations]
        assert "monitoring" in categories
        assert "incident_response" in categories
        assert "preventive" in categories
    
    def test_create_analysis_metadata(self):
        """Test analysis metadata creation."""
        flow_analysis = {"logs_analyzed": 150}
        
        metadata = self.engine._create_analysis_metadata(
            processing_time=1500,
            flow_analysis=flow_analysis,
            correlation_id="test-correlation-id"
        )
        
        assert metadata["processing_time_ms"] == 1500
        assert metadata["correlation_id"] == "test-correlation-id"
        assert metadata["logs_analyzed"] == 150
        assert "aws_guardduty" in metadata["data_sources"]
        assert "vpc_flow_logs" in metadata["data_sources"]
        assert metadata["analysis_version"] == "1.0"
        assert "timestamp" in metadata
    
    def test_create_analysis_metadata_no_flow_logs(self):
        """Test analysis metadata creation without flow logs."""
        metadata = self.engine._create_analysis_metadata(
            processing_time=1000,
            flow_analysis=None,
            correlation_id="test-correlation-id"
        )
        
        assert metadata["logs_analyzed"] == 0
        assert "aws_guardduty" in metadata["data_sources"]
        assert None in metadata["data_sources"]  # No VPC flow logs
    
    @patch('enrichment_engine.time.time')
    def test_enrich_finding_error_handling(self, mock_time, sample_finding):
        """Test error handling in enrich_finding method."""
        mock_time.side_effect = [1000.0, 1001.5]  # Start and end times
        
        # Create flow analysis that will cause an error in processing
        invalid_flow_analysis = {"invalid": "data"}
        
        # Should return base alert even if enrichment fails
        result = self.engine.enrich_finding(sample_finding, invalid_flow_analysis, "test-correlation-id")
        
        # Should have base alert structure
        assert result["finding_id"] == "test-finding-123"
        assert result["severity"] == 6.0
        # Should not have network_context or other enriched fields
        assert "network_context" not in result
    
    def test_calculate_confidence(self, sample_finding):
        """Test confidence calculation."""
        # High confidence pattern
        high_conf_pattern = {
            "pattern_type": "port_scanning",
            "evidence": {"unique_ports": 15, "source_ip": "1.2.3.4"}
        }
        sample_finding.severity = 8.0
        
        confidence = self.engine._calculate_confidence(high_conf_pattern, sample_finding)
        assert confidence == "high"
        
        # Low confidence pattern
        low_conf_pattern = {
            "pattern_type": "unknown",
            "evidence": {}
        }
        sample_finding.severity = 2.0
        sample_finding.network_interfaces = []
        sample_finding.remote_ip_details = []
        
        confidence = self.engine._calculate_confidence(low_conf_pattern, sample_finding)
        assert confidence == "low"