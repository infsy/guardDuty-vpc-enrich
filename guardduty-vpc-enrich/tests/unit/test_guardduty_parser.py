import pytest
from datetime import datetime
from unittest.mock import patch
import sys
import os

# Add lambda directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'lambda'))

from guardduty_parser import GuardDutyParser, GuardDutyFinding, NetworkInterface, RemoteIPDetails, PortDetails


class TestGuardDutyParser:
    
    def setup_method(self):
        self.parser = GuardDutyParser()
    
    @pytest.fixture
    def sample_guardduty_event(self):
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
                        "launchTime": "2024-01-15T10:00:00.000Z",
                        "platform": "null",
                        "productCodes": [],
                        "iamInstanceProfile": {
                            "arn": "arn:aws:iam::123456789012:instance-profile/test-profile",
                            "id": "AIPAI23HZ27SI6FQMGNQ2"
                        },
                        "networkInterfaces": [
                            {
                                "networkInterfaceId": "eni-12345678",
                                "privateIpAddress": "10.0.1.100",
                                "publicIp": "203.0.113.123",
                                "subnetId": "subnet-12345678",
                                "vpcId": "vpc-12345678",
                                "securityGroups": [
                                    {
                                        "groupId": "sg-12345678",
                                        "groupName": "default"
                                    }
                                ]
                            }
                        ],
                        "tags": [
                            {
                                "key": "Name",
                                "value": "test-instance"
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
                                    "localPortDetails": {
                                        "port": 22,
                                        "portName": "SSH"
                                    },
                                    "remoteIpDetails": {
                                        "ipAddressV4": "198.51.100.123",
                                        "organization": {
                                            "asn": "16509",
                                            "asnOrg": "AMAZON-02",
                                            "isp": "Amazon.com",
                                            "org": "Amazon.com"
                                        },
                                        "country": {
                                            "countryName": "United States"
                                        },
                                        "city": {
                                            "cityName": "Seattle"
                                        },
                                        "geoLocation": {
                                            "lat": 47.6062,
                                            "lon": -122.3321
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    "remoteIpDetails": {
                        "ipAddressV4": "198.51.100.123",
                        "organization": {
                            "asn": "16509",
                            "asnOrg": "AMAZON-02",
                            "isp": "Amazon.com",
                            "org": "Amazon.com"
                        },
                        "country": {
                            "countryName": "United States"
                        },
                        "city": {
                            "cityName": "Seattle"
                        },
                        "geoLocation": {
                            "lat": 47.6062,
                            "lon": -122.3321
                        }
                    },
                    "additionalInfo": {
                        "threatListName": "ProofPoint",
                        "sample": True
                    },
                    "archived": False,
                    "count": 1,
                    "eventFirstSeen": "2024-01-15T12:30:45.000Z",
                    "eventLastSeen": "2024-01-15T12:30:45.000Z",
                    "resourceRole": "TARGET"
                },
                "severity": 5.0,
                "createdAt": "2024-01-15T12:30:45.456Z",
                "updatedAt": "2024-01-15T12:30:45.456Z",
                "title": "Unprotected port on EC2 instance i-1234567890abcdef0 is being probed.",
                "description": "EC2 instance has an unprotected port which is being probed by a known malicious host."
            }
        }
    
    def test_parse_finding_success(self, sample_guardduty_event):
        """Test successful parsing of GuardDuty finding."""
        finding = self.parser.parse_finding(sample_guardduty_event)
        
        assert isinstance(finding, GuardDutyFinding)
        assert finding.finding_id == "test-finding-id-12345"
        assert finding.severity == 5.0
        assert finding.finding_type == "Recon:EC2/PortProbeUnprotectedPort"
        assert finding.account_id == "123456789012"
        assert finding.region == "us-east-1"
        assert finding.instance_id == "i-1234567890abcdef0"
        assert finding.resource_type == "Instance"
        
        # Check network interfaces
        assert len(finding.network_interfaces) == 1
        eni = finding.network_interfaces[0]
        assert eni.interface_id == "eni-12345678"
        assert eni.private_ip == "10.0.1.100"
        assert eni.public_ip == "203.0.113.123"
        assert eni.vpc_id == "vpc-12345678"
        assert eni.subnet_id == "subnet-12345678"
        assert "sg-12345678" in eni.security_groups
        
        # Check remote IP details
        assert len(finding.remote_ip_details) >= 1
        remote_ip = finding.remote_ip_details[0]
        assert remote_ip.ip_address == "198.51.100.123"
        assert remote_ip.country == "United States"
        assert remote_ip.city == "Seattle"
        assert remote_ip.organization == "Amazon.com"
        
        # Check port details
        assert len(finding.port_details) >= 1
        port = finding.port_details[0]
        assert port.port == 22
        assert port.port_name == "SSH"
    
    def test_parse_finding_invalid_source(self, sample_guardduty_event):
        """Test parsing fails with invalid event source."""
        sample_guardduty_event['source'] = 'aws.ec2'
        
        with pytest.raises(ValueError, match="Invalid event source"):
            self.parser.parse_finding(sample_guardduty_event)
    
    def test_parse_finding_invalid_detail_type(self, sample_guardduty_event):
        """Test parsing fails with invalid detail type."""
        sample_guardduty_event['detail-type'] = 'EC2 Instance State-change Notification'
        
        with pytest.raises(ValueError, match="Invalid detail type"):
            self.parser.parse_finding(sample_guardduty_event)
    
    def test_parse_finding_missing_required_fields(self, sample_guardduty_event):
        """Test parsing fails with missing required fields."""
        del sample_guardduty_event['detail']['id']
        
        with pytest.raises(ValueError, match="Missing required detail field"):
            self.parser.parse_finding(sample_guardduty_event)
    
    def test_parse_finding_malformed_timestamp(self, sample_guardduty_event):
        """Test parsing with malformed timestamp."""
        sample_guardduty_event['detail']['updatedAt'] = 'invalid-timestamp'
        
        with pytest.raises(ValueError):
            self.parser.parse_finding(sample_guardduty_event)
    
    def test_parse_finding_without_network_interfaces(self, sample_guardduty_event):
        """Test parsing finding without network interfaces."""
        del sample_guardduty_event['detail']['resource']['instanceDetails']['networkInterfaces']
        
        finding = self.parser.parse_finding(sample_guardduty_event)
        assert len(finding.network_interfaces) == 0
    
    def test_parse_finding_without_remote_ip_details(self, sample_guardduty_event):
        """Test parsing finding without remote IP details."""
        del sample_guardduty_event['detail']['service']['remoteIpDetails']
        del sample_guardduty_event['detail']['service']['action']['portProbeAction']['portProbeDetails']
        
        finding = self.parser.parse_finding(sample_guardduty_event)
        assert len(finding.remote_ip_details) == 0
    
    def test_get_primary_network_interface(self, sample_guardduty_event):
        """Test getting primary network interface."""
        finding = self.parser.parse_finding(sample_guardduty_event)
        primary_eni = self.parser.get_primary_network_interface(finding)
        
        assert primary_eni is not None
        assert primary_eni.interface_id == "eni-12345678"
        assert primary_eni.private_ip == "10.0.1.100"
    
    def test_get_primary_network_interface_none(self):
        """Test getting primary network interface when none exist."""
        finding = GuardDutyFinding(
            finding_id="test",
            severity=5.0,
            finding_type="test",
            timestamp=datetime.now(),
            title="test",
            description="test",
            region="us-east-1",
            account_id="123456789012",
            instance_id=None,
            resource_type="Instance",
            network_interfaces=[],
            remote_ip_details=[],
            port_details=[],
            raw_finding={}
        )
        
        primary_eni = self.parser.get_primary_network_interface(finding)
        assert primary_eni is None
    
    def test_get_target_ips(self, sample_guardduty_event):
        """Test getting target IPs for analysis."""
        finding = self.parser.parse_finding(sample_guardduty_event)
        target_ips = self.parser.get_target_ips(finding)
        
        assert "10.0.1.100" in target_ips  # Private IP
        assert "203.0.113.123" in target_ips  # Public IP
        assert "198.51.100.123" in target_ips  # Remote IP
        
        # Should not have duplicates
        assert len(target_ips) == len(set(target_ips))
    
    def test_get_target_ports(self, sample_guardduty_event):
        """Test getting target ports for analysis."""
        finding = self.parser.parse_finding(sample_guardduty_event)
        target_ports = self.parser.get_target_ports(finding)
        
        assert 22 in target_ports
        # Should not have duplicates
        assert len(target_ports) == len(set(target_ports))
    
    def test_parse_cryptocurrency_finding(self, sample_guardduty_event):
        """Test parsing cryptocurrency mining finding."""
        sample_guardduty_event['detail']['type'] = "CryptoCurrency:EC2/BitcoinTool.B!DNS"
        sample_guardduty_event['detail']['severity'] = 8.0
        
        finding = self.parser.parse_finding(sample_guardduty_event)
        
        assert finding.finding_type == "CryptoCurrency:EC2/BitcoinTool.B!DNS"
        assert finding.severity == 8.0
    
    def test_parse_network_connection_action(self, sample_guardduty_event):
        """Test parsing network connection action."""
        # Modify the event to have network connection action
        sample_guardduty_event['detail']['service']['action'] = {
            "actionType": "NETWORK_CONNECTION",
            "networkConnectionAction": {
                "blocked": False,
                "connectionDirection": "OUTBOUND",
                "localPortDetails": {
                    "port": 12345,
                    "portName": "Unknown"
                },
                "remoteIpDetails": {
                    "ipAddressV4": "203.0.113.200",
                    "country": {"countryName": "Example Country"},
                    "city": {"cityName": "Example City"},
                    "organization": {"orgName": "Example Org"}
                },
                "remotePortDetails": {
                    "port": 80,
                    "portName": "HTTP"
                },
                "protocol": "TCP"
            }
        }
        
        finding = self.parser.parse_finding(sample_guardduty_event)
        
        # Should have parsed both local and remote ports
        ports = [p.port for p in finding.port_details]
        assert 12345 in ports  # Local port
        assert 80 in ports  # Remote port
        
        # Should have parsed remote IP from action
        remote_ips = [ip.ip_address for ip in finding.remote_ip_details]
        assert "203.0.113.200" in remote_ips
    
    @patch('guardduty_parser.logger')
    def test_parse_finding_with_warnings(self, mock_logger, sample_guardduty_event):
        """Test parsing with malformed sub-components that generate warnings."""
        # Add malformed network interface
        sample_guardduty_event['detail']['resource']['instanceDetails']['networkInterfaces'].append({
            "networkInterfaceId": "",  # Empty ID should cause warning
            "malformed": True
        })
        
        finding = self.parser.parse_finding(sample_guardduty_event)
        
        # Should still parse successfully but generate warnings
        assert finding is not None
        # Should have only one valid network interface
        assert len(finding.network_interfaces) == 1
        
        # Check that warning was logged
        mock_logger.warning.assert_called()
    
    def test_validate_event_missing_fields(self):
        """Test event validation with missing fields."""
        invalid_event = {"source": "aws.guardduty"}  # Missing required fields
        
        with pytest.raises(ValueError, match="Missing required field"):
            self.parser._validate_event(invalid_event)
    
    def test_extract_instance_id_success(self, sample_guardduty_event):
        """Test instance ID extraction."""
        resource = sample_guardduty_event['detail']['resource']
        instance_id = self.parser._extract_instance_id(resource)
        
        assert instance_id == "i-1234567890abcdef0"
    
    def test_extract_instance_id_missing(self):
        """Test instance ID extraction when missing."""
        resource = {"resourceType": "Instance"}  # No instanceDetails
        instance_id = self.parser._extract_instance_id(resource)
        
        assert instance_id is None