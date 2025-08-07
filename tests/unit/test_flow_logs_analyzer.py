import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import gzip
import sys
import os

# Add lambda directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'lambda'))

from flow_logs_analyzer import FlowLogsAnalyzer, FlowLogEntry, TrafficSummary, TopTalker
from guardduty_parser import GuardDutyFinding, NetworkInterface, RemoteIPDetails, PortDetails


class TestFlowLogsAnalyzer:
    
    def setup_method(self):
        with patch.dict(os.environ, {
            'FLOW_LOGS_BUCKET': 'test-flow-logs-bucket',
            'TIME_WINDOW_BEFORE': '15',
            'TIME_WINDOW_AFTER': '15'
        }):
            self.analyzer = FlowLogsAnalyzer()
    
    @pytest.fixture
    def sample_finding(self):
        """Create a sample GuardDuty finding for testing."""
        return GuardDutyFinding(
            finding_id="test-finding-123",
            severity=6.0,
            finding_type="Recon:EC2/PortProbeUnprotectedPort",
            timestamp=datetime(2024, 1, 15, 12, 30, 45),
            title="Test Finding",
            description="Test Description",
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
                    is_malicious=False
                )
            ],
            port_details=[
                PortDetails(port=22, port_name="SSH"),
                PortDetails(port=80, port_name="HTTP")
            ],
            raw_finding={}
        )
    
    @pytest.fixture
    def sample_flow_logs(self):
        """Create sample VPC flow logs for testing."""
        return [
            FlowLogEntry(
                version="2",
                account_id="123456789012",
                interface_id="eni-12345678",
                srcaddr="10.0.1.100",
                dstaddr="198.51.100.123",
                srcport=12345,
                dstport=22,
                protocol=6,
                packets=10,
                bytes=1500,
                start=1705320645,  # 2024-01-15 12:30:45
                end=1705320655,    # 2024-01-15 12:30:55
                action="ACCEPT",
                log_status="OK"
            ),
            FlowLogEntry(
                version="2",
                account_id="123456789012",
                interface_id="eni-12345678",
                srcaddr="198.51.100.200",
                dstaddr="10.0.1.100",
                srcport=54321,
                dstport=80,
                protocol=6,
                packets=5,
                bytes=750,
                start=1705320650,
                end=1705320660,
                action="REJECT",
                log_status="OK"
            )
        ]
    
    def test_init_success(self):
        """Test successful initialization."""
        with patch.dict(os.environ, {
            'FLOW_LOGS_BUCKET': 'test-bucket',
            'TIME_WINDOW_BEFORE': '20',
            'TIME_WINDOW_AFTER': '10'
        }):
            analyzer = FlowLogsAnalyzer()
            assert analyzer.flow_logs_bucket == 'test-bucket'
            assert analyzer.time_window_before == 20
            assert analyzer.time_window_after == 10
    
    def test_init_missing_bucket(self):
        """Test initialization fails without bucket name."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="FLOW_LOGS_BUCKET environment variable not set"):
                FlowLogsAnalyzer()
    
    def test_calculate_time_window(self, sample_finding):
        """Test time window calculation."""
        start_time, end_time = self.analyzer._calculate_time_window(sample_finding.timestamp)
        
        expected_start = sample_finding.timestamp - timedelta(minutes=15)
        expected_end = sample_finding.timestamp + timedelta(minutes=15)
        
        assert start_time == expected_start
        assert end_time == expected_end
    
    def test_get_target_ips(self, sample_finding):
        """Test target IP extraction."""
        target_ips = self.analyzer._get_target_ips(sample_finding)
        
        assert "10.0.1.100" in target_ips
        assert "203.0.113.123" in target_ips
        assert "198.51.100.123" in target_ips
        assert len(target_ips) == 3
    
    def test_get_target_ports(self, sample_finding):
        """Test target port extraction."""
        target_ports = self.analyzer._get_target_ports(sample_finding)
        
        assert 22 in target_ports
        assert 80 in target_ports
        assert len(target_ports) == 2
    
    def test_generate_s3_prefixes(self):
        """Test S3 prefix generation."""
        start_time = datetime(2024, 1, 15, 10, 30, 45)
        end_time = datetime(2024, 1, 15, 14, 30, 45)
        account_id = "123456789012"
        region = "us-east-1"
        
        prefixes = self.analyzer._generate_s3_prefixes(start_time, end_time, account_id, region)
        
        expected_prefixes = [
            "AWSLogs/123456789012/vpcflowlogs/us-east-1/2024/01/15/",
        ]
        
        assert len(prefixes) == 1
        assert prefixes[0] in expected_prefixes
    
    def test_parse_flow_log_line_success(self):
        """Test successful flow log line parsing."""
        line = "2 123456789012 eni-12345678 10.0.1.100 198.51.100.123 12345 22 6 10 1500 1705320645 1705320655 ACCEPT OK"
        
        flow_log = self.analyzer._parse_flow_log_line(line)
        
        assert flow_log is not None
        assert flow_log.version == "2"
        assert flow_log.account_id == "123456789012"
        assert flow_log.srcaddr == "10.0.1.100"
        assert flow_log.dstaddr == "198.51.100.123"
        assert flow_log.srcport == 12345
        assert flow_log.dstport == 22
        assert flow_log.protocol == 6
        assert flow_log.packets == 10
        assert flow_log.bytes == 1500
        assert flow_log.action == "ACCEPT"
    
    def test_parse_flow_log_line_invalid(self):
        """Test flow log line parsing with invalid data."""
        # Too few fields
        line = "2 123456789012 eni-12345678"
        flow_log = self.analyzer._parse_flow_log_line(line)
        assert flow_log is None
        
        # Invalid numbers
        line = "2 123456789012 eni-12345678 10.0.1.100 198.51.100.123 abc 22 6 10 1500 1705320645 1705320655 ACCEPT OK"
        flow_log = self.analyzer._parse_flow_log_line(line)
        assert flow_log is None
    
    def test_parse_flow_log_line_with_dashes(self):
        """Test flow log line parsing with dash values."""
        line = "2 123456789012 eni-12345678 10.0.1.100 198.51.100.123 - - 6 10 1500 - - ACCEPT OK"
        
        flow_log = self.analyzer._parse_flow_log_line(line)
        
        assert flow_log is not None
        assert flow_log.srcport == 0
        assert flow_log.dstport == 0
        assert flow_log.start == 0
        assert flow_log.end == 0
    
    def test_is_relevant_flow_log(self, sample_finding):
        """Test flow log relevance checking."""
        target_ips = ["10.0.1.100", "198.51.100.123"]
        target_ports = [22, 80]
        start_time = datetime(2024, 1, 15, 12, 15, 0)
        end_time = datetime(2024, 1, 15, 12, 45, 0)
        
        # Relevant log (matching IP and port)
        relevant_log = FlowLogEntry(
            version="2", account_id="123456789012", interface_id="eni-12345678",
            srcaddr="10.0.1.100", dstaddr="198.51.100.200", srcport=12345, dstport=22,
            protocol=6, packets=10, bytes=1500, start=1705320645, end=1705320655,
            action="ACCEPT", log_status="OK"
        )
        
        assert self.analyzer._is_relevant_flow_log(relevant_log, target_ips, target_ports, start_time, end_time)
        
        # Non-relevant log (no matching IP)
        non_relevant_log = FlowLogEntry(
            version="2", account_id="123456789012", interface_id="eni-12345678",
            srcaddr="192.168.1.1", dstaddr="192.168.1.2", srcport=12345, dstport=22,
            protocol=6, packets=10, bytes=1500, start=1705320645, end=1705320655,
            action="ACCEPT", log_status="OK"
        )
        
        assert not self.analyzer._is_relevant_flow_log(non_relevant_log, target_ips, target_ports, start_time, end_time)
    
    def test_generate_traffic_summary(self, sample_flow_logs):
        """Test traffic summary generation."""
        target_ips = ["10.0.1.100"]
        
        summary = self.analyzer._generate_traffic_summary(sample_flow_logs, target_ips)
        
        assert summary["total_connections"] == 2
        assert summary["unique_remote_ips"] == 2  # 198.51.100.123, 198.51.100.200
        assert summary["total_bytes_in"] == 750    # Only inbound to 10.0.1.100
        assert summary["total_bytes_out"] == 1500  # Only outbound from 10.0.1.100
        assert summary["rejected_connections"] == 1
        assert 22 in summary["unique_ports"]
        assert 80 in summary["unique_ports"]
        assert summary["protocol_distribution"][6] == 2  # TCP
    
    def test_identify_top_talkers(self, sample_flow_logs):
        """Test top talkers identification."""
        target_ips = ["10.0.1.100"]
        
        top_talkers = self.analyzer._identify_top_talkers(sample_flow_logs, target_ips)
        
        assert len(top_talkers) == 2
        
        # Should be sorted by bytes (descending)
        assert top_talkers[0]["bytes"] >= top_talkers[1]["bytes"]
        
        # Check structure
        for talker in top_talkers:
            assert "ip" in talker
            assert "direction" in talker
            assert "bytes" in talker
            assert "packets" in talker
            assert "ports" in talker
            assert "connections" in talker
    
    def test_detect_port_scanning(self):
        """Test port scanning detection."""
        # Create flow logs showing port scanning pattern
        flow_logs = []
        for port in range(1, 15):  # 14 unique ports (above threshold of 10)
            flow_logs.append(FlowLogEntry(
                version="2", account_id="123456789012", interface_id="eni-12345678",
                srcaddr="198.51.100.100", dstaddr="10.0.1.100", srcport=54321, dstport=port,
                protocol=6, packets=1, bytes=64, start=1705320645, end=1705320655,
                action="REJECT", log_status="OK"
            ))
        
        target_ips = ["10.0.1.100"]
        patterns = self.analyzer._detect_port_scanning(flow_logs, target_ips)
        
        assert len(patterns) == 1
        assert patterns[0]["pattern_type"] == "port_scanning"
        assert "198.51.100.100" in patterns[0]["description"]
        assert patterns[0]["evidence"]["unique_ports"] == 14
    
    def test_detect_data_exfiltration(self):
        """Test data exfiltration detection."""
        # Create flow logs showing large data transfer (>100MB)
        large_transfer = 150 * 1024 * 1024  # 150MB
        flow_logs = [
            FlowLogEntry(
                version="2", account_id="123456789012", interface_id="eni-12345678",
                srcaddr="10.0.1.100", dstaddr="198.51.100.100", srcport=12345, dstport=80,
                protocol=6, packets=100000, bytes=large_transfer, start=1705320645, end=1705320655,
                action="ACCEPT", log_status="OK"
            )
        ]
        
        target_ips = ["10.0.1.100"]
        patterns = self.analyzer._detect_data_exfiltration(flow_logs, target_ips)
        
        assert len(patterns) == 1
        assert patterns[0]["pattern_type"] == "data_exfiltration"
        assert patterns[0]["evidence"]["bytes_transferred"] == large_transfer
        assert patterns[0]["evidence"]["mb_transferred"] == 150.0
    
    def test_detect_repeated_rejections(self):
        """Test repeated rejections detection."""
        # Create flow logs showing many rejected connections
        flow_logs = []
        for i in range(60):  # 60 rejected connections (above threshold of 50)
            flow_logs.append(FlowLogEntry(
                version="2", account_id="123456789012", interface_id="eni-12345678",
                srcaddr="198.51.100.100", dstaddr="10.0.1.100", srcport=54321, dstport=22,
                protocol=6, packets=1, bytes=64, start=1705320645, end=1705320655,
                action="REJECT", log_status="OK"
            ))
        
        patterns = self.analyzer._detect_repeated_rejections(flow_logs)
        
        assert len(patterns) == 1
        assert patterns[0]["pattern_type"] == "repeated_rejections"
        assert patterns[0]["evidence"]["rejected_connections"] == 60
    
    def test_detect_time_anomalies(self):
        """Test time anomalies detection."""
        # Create flow logs during unusual hours (3 AM)
        unusual_hour_timestamp = 1705287600  # 3 AM UTC
        flow_logs = []
        for i in range(15):  # 15 connections during unusual hours (above threshold of 10)
            flow_logs.append(FlowLogEntry(
                version="2", account_id="123456789012", interface_id="eni-12345678",
                srcaddr="10.0.1.100", dstaddr="198.51.100.100", srcport=12345, dstport=80,
                protocol=6, packets=1, bytes=64, start=unusual_hour_timestamp, end=unusual_hour_timestamp + 10,
                action="ACCEPT", log_status="OK"
            ))
        
        patterns = self.analyzer._detect_time_anomalies(flow_logs)
        
        assert len(patterns) == 1
        assert patterns[0]["pattern_type"] == "unusual_time_activity"
        assert patterns[0]["evidence"]["unusual_hour_connections"] == 15
    
    @patch('flow_logs_analyzer.boto3.client')
    def test_process_flow_log_file_gzip(self, mock_boto3):
        """Test processing gzipped flow log file."""
        # Mock S3 response with gzipped content
        mock_s3 = Mock()
        mock_boto3.return_value = mock_s3
        
        flow_log_content = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status\n"
        flow_log_content += "2 123456789012 eni-12345678 10.0.1.100 198.51.100.123 12345 22 6 10 1500 1705320645 1705320655 ACCEPT OK\n"
        
        compressed_content = gzip.compress(flow_log_content.encode('utf-8'))
        
        mock_response = {
            'Body': Mock()
        }
        mock_response['Body'].read.return_value = compressed_content
        mock_s3.get_object.return_value = mock_response
        
        target_ips = ["10.0.1.100", "198.51.100.123"]
        target_ports = [22]
        start_time = datetime(2024, 1, 15, 12, 15, 0)
        end_time = datetime(2024, 1, 15, 12, 45, 0)
        
        flow_logs = self.analyzer._process_flow_log_file(
            "test-key.gz", target_ips, target_ports, start_time, end_time
        )
        
        assert len(flow_logs) == 1
        assert flow_logs[0].srcaddr == "10.0.1.100"
        assert flow_logs[0].dstaddr == "198.51.100.123"
    
    @patch('flow_logs_analyzer.boto3.client')
    def test_process_flow_log_file_uncompressed(self, mock_boto3):
        """Test processing uncompressed flow log file."""
        mock_s3 = Mock()
        mock_boto3.return_value = mock_s3
        
        flow_log_content = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status\n"
        flow_log_content += "2 123456789012 eni-12345678 10.0.1.100 198.51.100.123 12345 22 6 10 1500 1705320645 1705320655 ACCEPT OK\n"
        
        mock_response = {
            'Body': Mock()
        }
        mock_response['Body'].read.return_value = flow_log_content.encode('utf-8')
        mock_s3.get_object.return_value = mock_response
        
        target_ips = ["10.0.1.100"]
        target_ports = [22]
        start_time = datetime(2024, 1, 15, 12, 15, 0)
        end_time = datetime(2024, 1, 15, 12, 45, 0)
        
        flow_logs = self.analyzer._process_flow_log_file(
            "test-key.txt", target_ips, target_ports, start_time, end_time
        )
        
        assert len(flow_logs) == 1
        assert flow_logs[0].srcaddr == "10.0.1.100"
    
    def test_is_object_in_time_range(self):
        """Test S3 object time range checking."""
        start_time = datetime(2024, 1, 15, 12, 0, 0)
        end_time = datetime(2024, 1, 15, 13, 0, 0)
        
        # Object within range
        key_in_range = "AWSLogs/123456789012/vpcflowlogs/us-east-1/2024/01/15/123456789012_vpcflowlogs_us-east-1_fl-12345_20240115T1230Z.log.gz"
        assert self.analyzer._is_object_in_time_range(key_in_range, start_time, end_time)
        
        # Object outside range
        key_out_range = "AWSLogs/123456789012/vpcflowlogs/us-east-1/2024/01/15/123456789012_vpcflowlogs_us-east-1_fl-12345_20240115T1400Z.log.gz"
        assert not self.analyzer._is_object_in_time_range(key_out_range, start_time, end_time)
        
        # Key without timestamp (should return True for safety)
        key_no_timestamp = "AWSLogs/123456789012/vpcflowlogs/us-east-1/2024/01/15/some-file.log"
        assert self.analyzer._is_object_in_time_range(key_no_timestamp, start_time, end_time)
    
    @patch('flow_logs_analyzer.boto3.client')
    def test_analyze_flows_success(self, mock_boto3, sample_finding):
        """Test complete flow analysis success."""
        # Mock S3 client and responses
        mock_s3 = Mock()
        mock_boto3.return_value = mock_s3
        
        # Mock paginator
        mock_paginator = Mock()
        mock_s3.get_paginator.return_value = mock_paginator
        
        # Mock pages with S3 objects
        mock_paginator.paginate.return_value = [
            {
                'Contents': [
                    {
                        'Key': 'AWSLogs/123456789012/vpcflowlogs/us-east-1/2024/01/15/test_20240115T1230Z.log.gz'
                    }
                ]
            }
        ]
        
        # Mock flow log file content
        flow_log_content = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status\n"
        flow_log_content += "2 123456789012 eni-12345678 10.0.1.100 198.51.100.123 12345 22 6 10 1500 1705320645 1705320655 ACCEPT OK\n"
        
        compressed_content = gzip.compress(flow_log_content.encode('utf-8'))
        mock_response = {'Body': Mock()}
        mock_response['Body'].read.return_value = compressed_content
        mock_s3.get_object.return_value = mock_response
        
        # Run analysis
        result = self.analyzer.analyze_flows(sample_finding, "test-correlation-id")
        
        assert result is not None
        assert "time_window" in result
        assert "traffic_summary" in result
        assert "top_talkers" in result
        assert "suspicious_patterns" in result
        assert result["logs_analyzed"] == 1
    
    @patch('flow_logs_analyzer.boto3.client')
    def test_analyze_flows_no_logs_found(self, mock_boto3, sample_finding):
        """Test flow analysis when no logs are found."""
        mock_s3 = Mock()
        mock_boto3.return_value = mock_s3
        
        # Mock empty paginator response
        mock_paginator = Mock()
        mock_s3.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{}]  # Empty response
        
        result = self.analyzer.analyze_flows(sample_finding, "test-correlation-id")
        
        assert result is None
    
    def test_analyze_flows_no_target_ips(self):
        """Test flow analysis when no target IPs are found."""
        finding_no_ips = GuardDutyFinding(
            finding_id="test", severity=5.0, finding_type="test",
            timestamp=datetime.now(), title="test", description="test",
            region="us-east-1", account_id="123456789012",
            instance_id=None, resource_type="Instance",
            network_interfaces=[], remote_ip_details=[], port_details=[],
            raw_finding={}
        )
        
        result = self.analyzer.analyze_flows(finding_no_ips, "test-correlation-id")
        
        assert result is None