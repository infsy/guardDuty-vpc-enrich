import gzip
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from guardduty_parser import GuardDutyFinding

logger = logging.getLogger(__name__)


@dataclass
class FlowLogEntry:
    """Individual VPC Flow Log entry."""
    version: str
    account_id: str
    interface_id: str
    srcaddr: str
    dstaddr: str
    srcport: int
    dstport: int
    protocol: int
    packets: int
    bytes: int
    start: int
    end: int
    action: str
    log_status: str


@dataclass
class TrafficSummary:
    """Traffic summary statistics."""
    total_connections: int
    unique_remote_ips: int
    total_bytes_in: int
    total_bytes_out: int
    rejected_connections: int
    unique_ports: Set[int]
    protocol_distribution: Dict[int, int]


@dataclass
class TopTalker:
    """Top communicating IP address."""
    ip: str
    direction: str  # 'inbound' or 'outbound'
    bytes: int
    packets: int
    ports: Set[int]
    connections: int


class FlowLogsAnalyzer:
    """Analyzer for VPC Flow Logs stored in S3."""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.s3_client = boto3.client('s3')
        self.flow_logs_bucket = os.environ.get('FLOW_LOGS_BUCKET')
        self.time_window_before = int(os.environ.get('TIME_WINDOW_BEFORE', '15'))
        self.time_window_after = int(os.environ.get('TIME_WINDOW_AFTER', '15'))
        
        if not self.flow_logs_bucket:
            raise ValueError("FLOW_LOGS_BUCKET environment variable not set")
    
    def analyze_flows(
        self, 
        finding_data: GuardDutyFinding, 
        correlation_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze VPC Flow Logs for the given GuardDuty finding.
        
        Args:
            finding_data: Parsed GuardDuty finding
            correlation_id: Correlation ID for logging
            
        Returns:
            Dict containing flow analysis results, None if no relevant logs found
        """
        try:
            # Calculate time window
            start_time, end_time = self._calculate_time_window(finding_data.timestamp)
            
            self.logger.info(
                f"Analyzing flow logs for time window {start_time} to {end_time}",
                extra={
                    "correlation_id": correlation_id,
                    "finding_id": finding_data.finding_id
                }
            )
            
            # Get target IPs and ports for analysis
            target_ips = self._get_target_ips(finding_data)
            target_ports = self._get_target_ports(finding_data)
            
            if not target_ips:
                self.logger.warning(
                    "No target IPs found for flow logs analysis",
                    extra={"correlation_id": correlation_id, "finding_id": finding_data.finding_id}
                )
                return None
            
            # Find and analyze relevant flow log files
            flow_logs = self._fetch_flow_logs(
                start_time=start_time,
                end_time=end_time,
                target_ips=target_ips,
                target_ports=target_ports,
                account_id=finding_data.account_id,
                region=finding_data.region,
                correlation_id=correlation_id
            )
            
            if not flow_logs:
                return None
            
            # Analyze the flow logs
            analysis = self._analyze_flow_logs(
                flow_logs=flow_logs,
                target_ips=target_ips,
                finding_data=finding_data,
                correlation_id=correlation_id
            )
            
            return {
                "time_window": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat()
                },
                "target_ips": target_ips,
                "target_ports": target_ports,
                "logs_analyzed": len(flow_logs),
                "traffic_summary": analysis["traffic_summary"],
                "top_talkers": analysis["top_talkers"],
                "suspicious_patterns": analysis["suspicious_patterns"],
                "raw_flow_logs": analysis["raw_samples"][:50]  # Limit samples
            }
            
        except Exception as e:
            self.logger.error(
                f"Failed to analyze flow logs: {str(e)}",
                extra={"correlation_id": correlation_id},
                exc_info=True
            )
            return None
    
    def _calculate_time_window(self, finding_timestamp: datetime) -> Tuple[datetime, datetime]:
        """Calculate the time window for flow logs analysis."""
        start_time = finding_timestamp - timedelta(minutes=self.time_window_before)
        end_time = finding_timestamp + timedelta(minutes=self.time_window_after)
        return start_time, end_time
    
    def _get_target_ips(self, finding_data: GuardDutyFinding) -> List[str]:
        """Extract target IPs from the GuardDuty finding."""
        target_ips = []
        
        # Add private IPs from network interfaces
        for eni in finding_data.network_interfaces:
            if eni.private_ip:
                target_ips.append(eni.private_ip)
            if eni.public_ip:
                target_ips.append(eni.public_ip)
        
        # Add remote IPs
        for remote_ip in finding_data.remote_ip_details:
            if remote_ip.ip_address:
                target_ips.append(remote_ip.ip_address)
        
        return list(set(target_ips))
    
    def _get_target_ports(self, finding_data: GuardDutyFinding) -> List[int]:
        """Extract target ports from the GuardDuty finding."""
        ports = []
        for port_detail in finding_data.port_details:
            if port_detail.port > 0:
                ports.append(port_detail.port)
        return list(set(ports))
    
    def _fetch_flow_logs(
        self,
        start_time: datetime,
        end_time: datetime,
        target_ips: List[str],
        target_ports: List[int],
        account_id: str,
        region: str,
        correlation_id: str
    ) -> List[FlowLogEntry]:
        """Fetch and filter flow logs from S3."""
        all_flow_logs = []
        
        # Generate S3 prefixes for the time range
        prefixes = self._generate_s3_prefixes(start_time, end_time, account_id, region)
        
        self.logger.info(
            f"Searching {len(prefixes)} S3 prefixes for flow logs",
            extra={"correlation_id": correlation_id}
        )
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_prefix = {
                executor.submit(
                    self._process_s3_prefix, 
                    prefix, 
                    target_ips, 
                    target_ports,
                    start_time, 
                    end_time,
                    correlation_id
                ): prefix for prefix in prefixes
            }
            
            for future in as_completed(future_to_prefix):
                prefix = future_to_prefix[future]
                try:
                    flow_logs = future.result()
                    all_flow_logs.extend(flow_logs)
                    self.logger.debug(
                        f"Processed prefix {prefix}: {len(flow_logs)} matching logs",
                        extra={"correlation_id": correlation_id}
                    )
                except Exception as e:
                    self.logger.warning(
                        f"Failed to process prefix {prefix}: {str(e)}",
                        extra={"correlation_id": correlation_id}
                    )
        
        self.logger.info(
            f"Found {len(all_flow_logs)} relevant flow log entries",
            extra={"correlation_id": correlation_id}
        )
        
        return all_flow_logs
    
    def _generate_s3_prefixes(
        self, 
        start_time: datetime, 
        end_time: datetime, 
        account_id: str, 
        region: str
    ) -> List[str]:
        """Generate S3 prefixes for the time range."""
        prefixes = []
        current = start_time.replace(minute=0, second=0, microsecond=0)
        
        while current <= end_time:
            prefix = f"AWSLogs/{account_id}/vpcflowlogs/{region}/{current.year:04d}/{current.month:02d}/{current.day:02d}/"
            if prefix not in prefixes:
                prefixes.append(prefix)
            current += timedelta(hours=1)
        
        return prefixes
    
    def _process_s3_prefix(
        self,
        prefix: str,
        target_ips: List[str],
        target_ports: List[int],
        start_time: datetime,
        end_time: datetime,
        correlation_id: str
    ) -> List[FlowLogEntry]:
        """Process flow logs from a single S3 prefix."""
        flow_logs = []
        
        try:
            # List objects in the prefix
            paginator = self.s3_client.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=self.flow_logs_bucket, Prefix=prefix)
            
            for page in page_iterator:
                if 'Contents' not in page:
                    continue
                
                for obj in page['Contents']:
                    key = obj['Key']
                    
                    # Filter by time range based on object key
                    if not self._is_object_in_time_range(key, start_time, end_time):
                        continue
                    
                    try:
                        # Download and process the file
                        file_flow_logs = self._process_flow_log_file(
                            key, target_ips, target_ports, start_time, end_time
                        )
                        flow_logs.extend(file_flow_logs)
                        
                        # Limit the number of logs processed to prevent memory issues
                        if len(flow_logs) > 10000:
                            self.logger.warning(
                                f"Flow logs limit reached (10000), stopping processing for prefix {prefix}",
                                extra={"correlation_id": correlation_id}
                            )
                            break
                            
                    except Exception as e:
                        self.logger.warning(
                            f"Failed to process flow log file {key}: {str(e)}",
                            extra={"correlation_id": correlation_id}
                        )
        
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchKey':
                self.logger.warning(
                    f"S3 error processing prefix {prefix}: {str(e)}",
                    extra={"correlation_id": correlation_id}
                )
        
        return flow_logs
    
    def _is_object_in_time_range(self, key: str, start_time: datetime, end_time: datetime) -> bool:
        """Check if S3 object is within the target time range based on key."""
        # Extract timestamp from key if possible
        # VPC Flow Logs format: AWSLogs/account/vpcflowlogs/region/year/month/day/filename_timestamp.gz
        timestamp_match = re.search(r'(\d{8}T\d{4}Z)', key)
        if timestamp_match:
            try:
                obj_timestamp = datetime.strptime(timestamp_match.group(1), '%Y%m%dT%H%MZ')
                return start_time <= obj_timestamp <= end_time
            except ValueError:
                pass
        
        # If can't parse timestamp from key, include it (safer approach)
        return True
    
    def _process_flow_log_file(
        self,
        s3_key: str,
        target_ips: List[str],
        target_ports: List[int],
        start_time: datetime,
        end_time: datetime
    ) -> List[FlowLogEntry]:
        """Process a single flow log file from S3."""
        flow_logs = []
        
        try:
            # Download the file
            response = self.s3_client.get_object(Bucket=self.flow_logs_bucket, Key=s3_key)
            
            # Handle gzip compression
            if s3_key.endswith('.gz'):
                content = gzip.decompress(response['Body'].read()).decode('utf-8')
            else:
                content = response['Body'].read().decode('utf-8')
            
            # Parse flow log entries
            for line_num, line in enumerate(content.strip().split('\n')):
                if not line or line.startswith('version'):  # Skip header
                    continue
                
                try:
                    flow_log = self._parse_flow_log_line(line)
                    if flow_log and self._is_relevant_flow_log(
                        flow_log, target_ips, target_ports, start_time, end_time
                    ):
                        flow_logs.append(flow_log)
                        
                except Exception as e:
                    self.logger.debug(f"Failed to parse line {line_num} in {s3_key}: {str(e)}")
                    continue
        
        except ClientError as e:
            raise Exception(f"S3 error: {str(e)}")
        
        return flow_logs
    
    def _parse_flow_log_line(self, line: str) -> Optional[FlowLogEntry]:
        """Parse a single flow log line."""
        try:
            fields = line.strip().split(' ')
            if len(fields) < 14:
                return None
            
            return FlowLogEntry(
                version=fields[0],
                account_id=fields[1],
                interface_id=fields[2],
                srcaddr=fields[3],
                dstaddr=fields[4],
                srcport=int(fields[5]) if fields[5] != '-' else 0,
                dstport=int(fields[6]) if fields[6] != '-' else 0,
                protocol=int(fields[7]) if fields[7] != '-' else 0,
                packets=int(fields[8]) if fields[8] != '-' else 0,
                bytes=int(fields[9]) if fields[9] != '-' else 0,
                start=int(fields[10]) if fields[10] != '-' else 0,
                end=int(fields[11]) if fields[11] != '-' else 0,
                action=fields[12],
                log_status=fields[13]
            )
        except (ValueError, IndexError):
            return None
    
    def _is_relevant_flow_log(
        self,
        flow_log: FlowLogEntry,
        target_ips: List[str],
        target_ports: List[int],
        start_time: datetime,
        end_time: datetime
    ) -> bool:
        """Check if flow log entry is relevant to the GuardDuty finding."""
        # Check time range
        if flow_log.start > 0 and flow_log.end > 0:
            log_start = datetime.fromtimestamp(flow_log.start)
            log_end = datetime.fromtimestamp(flow_log.end)
            
            if not (log_start <= end_time and log_end >= start_time):
                return False
        
        # Check if source or destination IP matches target IPs
        ip_match = (
            flow_log.srcaddr in target_ips or 
            flow_log.dstaddr in target_ips
        )
        
        if not ip_match:
            return False
        
        # Check ports if specified
        if target_ports:
            port_match = (
                flow_log.srcport in target_ports or 
                flow_log.dstport in target_ports
            )
            return port_match
        
        return True
    
    def _analyze_flow_logs(
        self,
        flow_logs: List[FlowLogEntry],
        target_ips: List[str],
        finding_data: GuardDutyFinding,
        correlation_id: str
    ) -> Dict[str, Any]:
        """Analyze flow logs and generate insights."""
        traffic_summary = self._generate_traffic_summary(flow_logs, target_ips)
        top_talkers = self._identify_top_talkers(flow_logs, target_ips)
        suspicious_patterns = self._detect_suspicious_patterns(flow_logs, target_ips, finding_data)
        
        # Sample of raw flow logs for reference
        raw_samples = []
        for log in flow_logs[:20]:  # First 20 entries
            raw_samples.append({
                "srcaddr": log.srcaddr,
                "dstaddr": log.dstaddr,
                "srcport": log.srcport,
                "dstport": log.dstport,
                "protocol": log.protocol,
                "bytes": log.bytes,
                "packets": log.packets,
                "action": log.action,
                "start": log.start,
                "end": log.end
            })
        
        return {
            "traffic_summary": traffic_summary,
            "top_talkers": top_talkers,
            "suspicious_patterns": suspicious_patterns,
            "raw_samples": raw_samples
        }
    
    def _generate_traffic_summary(self, flow_logs: List[FlowLogEntry], target_ips: List[str]) -> Dict[str, Any]:
        """Generate traffic summary statistics."""
        unique_remote_ips = set()
        unique_ports = set()
        protocol_dist = {}
        total_bytes_in = 0
        total_bytes_out = 0
        rejected_connections = 0
        
        for log in flow_logs:
            # Track remote IPs
            if log.srcaddr in target_ips:
                unique_remote_ips.add(log.dstaddr)
                total_bytes_out += log.bytes
            else:
                unique_remote_ips.add(log.srcaddr)
                total_bytes_in += log.bytes
            
            # Track ports
            if log.srcport > 0:
                unique_ports.add(log.srcport)
            if log.dstport > 0:
                unique_ports.add(log.dstport)
            
            # Protocol distribution
            protocol_dist[log.protocol] = protocol_dist.get(log.protocol, 0) + 1
            
            # Rejected connections
            if log.action == 'REJECT':
                rejected_connections += 1
        
        return {
            "total_connections": len(flow_logs),
            "unique_remote_ips": len(unique_remote_ips),
            "total_bytes_in": total_bytes_in,
            "total_bytes_out": total_bytes_out,
            "rejected_connections": rejected_connections,
            "unique_ports": list(unique_ports),
            "protocol_distribution": protocol_dist
        }
    
    def _identify_top_talkers(self, flow_logs: List[FlowLogEntry], target_ips: List[str]) -> List[Dict[str, Any]]:
        """Identify top communicating IP addresses."""
        talker_stats = {}
        
        for log in flow_logs:
            if log.srcaddr in target_ips:
                # Outbound traffic
                remote_ip = log.dstaddr
                direction = 'outbound'
            else:
                # Inbound traffic
                remote_ip = log.srcaddr
                direction = 'inbound'
            
            key = f"{remote_ip}_{direction}"
            if key not in talker_stats:
                talker_stats[key] = {
                    'ip': remote_ip,
                    'direction': direction,
                    'bytes': 0,
                    'packets': 0,
                    'ports': set(),
                    'connections': 0
                }
            
            talker_stats[key]['bytes'] += log.bytes
            talker_stats[key]['packets'] += log.packets
            talker_stats[key]['connections'] += 1
            talker_stats[key]['ports'].add(log.srcport)
            talker_stats[key]['ports'].add(log.dstport)
        
        # Sort by bytes and return top 10
        sorted_talkers = sorted(
            talker_stats.values(),
            key=lambda x: x['bytes'],
            reverse=True
        )[:10]
        
        # Convert ports set to list for JSON serialization
        for talker in sorted_talkers:
            talker['ports'] = list(talker['ports'])
        
        return sorted_talkers
    
    def _detect_suspicious_patterns(
        self,
        flow_logs: List[FlowLogEntry],
        target_ips: List[str],
        finding_data: GuardDutyFinding
    ) -> List[Dict[str, Any]]:
        """Detect suspicious patterns in flow logs."""
        patterns = []
        
        # Pattern 1: Port scanning (multiple unique ports from same IP)
        patterns.extend(self._detect_port_scanning(flow_logs, target_ips))
        
        # Pattern 2: Data exfiltration (large outbound traffic)
        patterns.extend(self._detect_data_exfiltration(flow_logs, target_ips))
        
        # Pattern 3: Repeated rejected connections
        patterns.extend(self._detect_repeated_rejections(flow_logs))
        
        # Pattern 4: Unusual time patterns (if we have timing data)
        patterns.extend(self._detect_time_anomalies(flow_logs))
        
        return patterns
    
    def _detect_port_scanning(self, flow_logs: List[FlowLogEntry], target_ips: List[str]) -> List[Dict[str, Any]]:
        """Detect port scanning patterns."""
        patterns = []
        ip_ports = {}
        
        for log in flow_logs:
            remote_ip = log.srcaddr if log.dstaddr in target_ips else log.dstaddr
            
            if remote_ip not in ip_ports:
                ip_ports[remote_ip] = set()
            ip_ports[remote_ip].add(log.dstport if log.dstaddr in target_ips else log.srcport)
        
        for ip, ports in ip_ports.items():
            if len(ports) > 10:  # More than 10 unique ports
                patterns.append({
                    "pattern_type": "port_scanning",
                    "description": f"Port scanning detected from {ip}",
                    "evidence": {
                        "source_ip": ip,
                        "unique_ports": len(ports),
                        "ports_accessed": list(ports)[:20]  # Limit for readability
                    }
                })
        
        return patterns
    
    def _detect_data_exfiltration(self, flow_logs: List[FlowLogEntry], target_ips: List[str]) -> List[Dict[str, Any]]:
        """Detect potential data exfiltration patterns."""
        patterns = []
        outbound_traffic = {}
        
        for log in flow_logs:
            if log.srcaddr in target_ips:  # Outbound traffic
                remote_ip = log.dstaddr
                if remote_ip not in outbound_traffic:
                    outbound_traffic[remote_ip] = 0
                outbound_traffic[remote_ip] += log.bytes
        
        # Threshold: 100MB outbound to single IP
        for ip, bytes_sent in outbound_traffic.items():
            if bytes_sent > 100 * 1024 * 1024:
                patterns.append({
                    "pattern_type": "data_exfiltration",
                    "description": f"Large outbound data transfer to {ip}",
                    "evidence": {
                        "destination_ip": ip,
                        "bytes_transferred": bytes_sent,
                        "mb_transferred": round(bytes_sent / (1024 * 1024), 2)
                    }
                })
        
        return patterns
    
    def _detect_repeated_rejections(self, flow_logs: List[FlowLogEntry]) -> List[Dict[str, Any]]:
        """Detect repeated rejected connections."""
        patterns = []
        rejected_by_ip = {}
        
        for log in flow_logs:
            if log.action == 'REJECT':
                ip = log.srcaddr
                if ip not in rejected_by_ip:
                    rejected_by_ip[ip] = 0
                rejected_by_ip[ip] += 1
        
        for ip, count in rejected_by_ip.items():
            if count > 50:  # More than 50 rejected connections
                patterns.append({
                    "pattern_type": "repeated_rejections",
                    "description": f"High number of rejected connections from {ip}",
                    "evidence": {
                        "source_ip": ip,
                        "rejected_connections": count
                    }
                })
        
        return patterns
    
    def _detect_time_anomalies(self, flow_logs: List[FlowLogEntry]) -> List[Dict[str, Any]]:
        """Detect time-based anomalies."""
        patterns = []
        
        # Check for activity during unusual hours (example: 2-6 AM)
        unusual_hours = set(range(2, 6))
        unusual_activity = 0
        
        for log in flow_logs:
            if log.start > 0:
                hour = datetime.fromtimestamp(log.start).hour
                if hour in unusual_hours:
                    unusual_activity += 1
        
        if unusual_activity > 10:  # More than 10 connections during unusual hours
            patterns.append({
                "pattern_type": "unusual_time_activity",
                "description": "Network activity during unusual hours (2-6 AM)",
                "evidence": {
                    "unusual_hour_connections": unusual_activity,
                    "time_range": "02:00-06:00"
                }
            })
        
        return patterns