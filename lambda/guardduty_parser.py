import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any, Optional, List
import json

logger = logging.getLogger(__name__)


@dataclass
class NetworkInterface:
    """Network interface information from GuardDuty finding."""
    interface_id: str
    private_ip: str
    public_ip: Optional[str]
    vpc_id: str
    subnet_id: str
    security_groups: List[str]


@dataclass
class RemoteIPDetails:
    """Remote IP details from GuardDuty finding."""
    ip_address: str
    country: Optional[str]
    city: Optional[str]
    organization: Optional[str]
    is_malicious: bool = False


@dataclass
class PortDetails:
    """Port information from GuardDuty finding."""
    port: int
    port_name: Optional[str]
    
    
@dataclass
class GuardDutyFinding:
    """Structured GuardDuty finding data."""
    finding_id: str
    severity: float
    finding_type: str
    timestamp: datetime
    title: str
    description: str
    region: str
    account_id: str
    
    # Resource details
    instance_id: Optional[str]
    resource_type: str
    
    # Network details
    network_interfaces: List[NetworkInterface]
    remote_ip_details: List[RemoteIPDetails]
    port_details: List[PortDetails]
    
    # Raw finding for reference
    raw_finding: Dict[str, Any]


class GuardDutyParser:
    """Parser for GuardDuty EventBridge events."""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def parse_finding(self, event: Dict[str, Any]) -> GuardDutyFinding:
        """
        Parse GuardDuty finding from EventBridge event.
        
        Args:
            event: EventBridge event containing GuardDuty finding
            
        Returns:
            GuardDutyFinding object with parsed data
            
        Raises:
            ValueError: If event is invalid or missing required fields
        """
        try:
            # Validate event structure
            self._validate_event(event)
            
            detail = event['detail']
            
            # Extract basic finding information
            finding_id = detail['id']
            severity = float(detail['severity'])
            finding_type = detail['type']
            timestamp = datetime.fromisoformat(detail['updatedAt'].replace('Z', '+00:00'))
            title = detail['title']
            description = detail['description']
            region = detail['region']
            account_id = detail['accountId']
            
            # Parse resource information
            resource = detail.get('resource', {})
            instance_id = self._extract_instance_id(resource)
            resource_type = resource.get('resourceType', 'Unknown')
            
            # Parse network interfaces
            network_interfaces = self._parse_network_interfaces(resource)
            
            # Parse remote IP details
            remote_ip_details = self._parse_remote_ip_details(detail)
            
            # Parse port details
            port_details = self._parse_port_details(detail)
            
            finding = GuardDutyFinding(
                finding_id=finding_id,
                severity=severity,
                finding_type=finding_type,
                timestamp=timestamp,
                title=title,
                description=description,
                region=region,
                account_id=account_id,
                instance_id=instance_id,
                resource_type=resource_type,
                network_interfaces=network_interfaces,
                remote_ip_details=remote_ip_details,
                port_details=port_details,
                raw_finding=detail
            )
            
            self.logger.info(
                f"Successfully parsed GuardDuty finding",
                extra={
                    "finding_id": finding_id,
                    "severity": severity,
                    "finding_type": finding_type,
                    "resource_type": resource_type,
                    "network_interfaces_count": len(network_interfaces)
                }
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Failed to parse GuardDuty finding: {str(e)}")
            raise ValueError(f"Invalid GuardDuty finding format: {str(e)}")
    
    def _validate_event(self, event: Dict[str, Any]) -> None:
        """Validate EventBridge event structure."""
        required_fields = ['source', 'detail-type', 'detail']
        for field in required_fields:
            if field not in event:
                raise ValueError(f"Missing required field: {field}")
        
        if event['source'] != 'aws.guardduty':
            raise ValueError(f"Invalid event source: {event['source']}")
        
        if event['detail-type'] != 'GuardDuty Finding':
            raise ValueError(f"Invalid detail type: {event['detail-type']}")
        
        detail = event['detail']
        required_detail_fields = ['id', 'severity', 'type', 'updatedAt', 'title', 'description']
        for field in required_detail_fields:
            if field not in detail:
                raise ValueError(f"Missing required detail field: {field}")
    
    def _extract_instance_id(self, resource: Dict[str, Any]) -> Optional[str]:
        """Extract EC2 instance ID from resource details."""
        instance_details = resource.get('instanceDetails', {})
        return instance_details.get('instanceId')
    
    def _parse_network_interfaces(self, resource: Dict[str, Any]) -> List[NetworkInterface]:
        """Parse network interface details from resource."""
        interfaces = []
        
        instance_details = resource.get('instanceDetails', {})
        network_interfaces = instance_details.get('networkInterfaces', [])
        
        for eni in network_interfaces:
            try:
                # Extract security groups
                security_groups = []
                for sg in eni.get('securityGroups', []):
                    security_groups.append(sg.get('groupId', ''))
                
                interface = NetworkInterface(
                    interface_id=eni.get('networkInterfaceId', ''),
                    private_ip=eni.get('privateIpAddress', ''),
                    public_ip=eni.get('publicIp'),
                    vpc_id=eni.get('vpcId', ''),
                    subnet_id=eni.get('subnetId', ''),
                    security_groups=security_groups
                )
                interfaces.append(interface)
                
            except Exception as e:
                self.logger.warning(f"Failed to parse network interface: {str(e)}")
                continue
        
        return interfaces
    
    def _parse_remote_ip_details(self, detail: Dict[str, Any]) -> List[RemoteIPDetails]:
        """Parse remote IP details from finding."""
        remote_ips = []
        
        # Check service section for network connection details
        service = detail.get('service', {})
        
        # Parse from remoteIpDetails
        remote_ip_details = service.get('remoteIpDetails', {})
        if remote_ip_details:
            try:
                geo_location = remote_ip_details.get('geoLocation', {})
                organization = remote_ip_details.get('organization', {})
                
                remote_ip = RemoteIPDetails(
                    ip_address=remote_ip_details.get('ipAddressV4', ''),
                    country=geo_location.get('countryName'),
                    city=geo_location.get('cityName'),
                    organization=organization.get('orgName'),
                    is_malicious=remote_ip_details.get('threatIntelDetails', {}).get('threatNames', []) != []
                )
                remote_ips.append(remote_ip)
                
            except Exception as e:
                self.logger.warning(f"Failed to parse remote IP details: {str(e)}")
        
        # Parse from action details (for different finding types)
        action = service.get('action', {})
        if action:
            # Network connection action
            network_connection = action.get('networkConnectionAction', {})
            if network_connection:
                remote_ip_detail = network_connection.get('remoteIpDetails', {})
                if remote_ip_detail and remote_ip_detail.get('ipAddressV4'):
                    try:
                        geo_location = remote_ip_detail.get('geoLocation', {})
                        organization = remote_ip_detail.get('organization', {})
                        
                        remote_ip = RemoteIPDetails(
                            ip_address=remote_ip_detail.get('ipAddressV4'),
                            country=geo_location.get('countryName'),
                            city=geo_location.get('cityName'),
                            organization=organization.get('orgName'),
                            is_malicious=remote_ip_detail.get('threatIntelDetails', {}).get('threatNames', []) != []
                        )
                        remote_ips.append(remote_ip)
                        
                    except Exception as e:
                        self.logger.warning(f"Failed to parse action remote IP details: {str(e)}")
        
        return remote_ips
    
    def _parse_port_details(self, detail: Dict[str, Any]) -> List[PortDetails]:
        """Parse port details from finding."""
        ports = []
        
        service = detail.get('service', {})
        action = service.get('action', {})
        
        # Network connection action ports
        network_connection = action.get('networkConnectionAction', {})
        if network_connection:
            # Remote port
            remote_port_details = network_connection.get('remotePortDetails', {})
            if remote_port_details:
                try:
                    port = PortDetails(
                        port=remote_port_details.get('port', 0),
                        port_name=remote_port_details.get('portName')
                    )
                    ports.append(port)
                except Exception as e:
                    self.logger.warning(f"Failed to parse remote port details: {str(e)}")
            
            # Local port
            local_port_details = network_connection.get('localPortDetails', {})
            if local_port_details:
                try:
                    port = PortDetails(
                        port=local_port_details.get('port', 0),
                        port_name=local_port_details.get('portName')
                    )
                    ports.append(port)
                except Exception as e:
                    self.logger.warning(f"Failed to parse local port details: {str(e)}")
        
        # Port probe action
        port_probe = action.get('portProbeAction', {})
        if port_probe:
            port_probe_details = port_probe.get('portProbeDetails', [])
            for port_detail in port_probe_details:
                try:
                    port = PortDetails(
                        port=port_detail.get('localPortDetails', {}).get('port', 0),
                        port_name=port_detail.get('localPortDetails', {}).get('portName')
                    )
                    ports.append(port)
                except Exception as e:
                    self.logger.warning(f"Failed to parse port probe details: {str(e)}")
        
        return ports
    
    def get_primary_network_interface(self, finding: GuardDutyFinding) -> Optional[NetworkInterface]:
        """Get the primary network interface from the finding."""
        if not finding.network_interfaces:
            return None
        
        # Return the first interface (typically the primary)
        return finding.network_interfaces[0]
    
    def get_target_ips(self, finding: GuardDutyFinding) -> List[str]:
        """Get all target IP addresses for flow logs analysis."""
        ips = []
        
        # Add private IPs from network interfaces
        for eni in finding.network_interfaces:
            if eni.private_ip:
                ips.append(eni.private_ip)
            if eni.public_ip:
                ips.append(eni.public_ip)
        
        # Add remote IPs
        for remote_ip in finding.remote_ip_details:
            if remote_ip.ip_address:
                ips.append(remote_ip.ip_address)
        
        return list(set(ips))  # Remove duplicates
    
    def get_target_ports(self, finding: GuardDutyFinding) -> List[int]:
        """Get all target ports for flow logs analysis."""
        ports = []
        
        for port_detail in finding.port_details:
            if port_detail.port > 0:
                ports.append(port_detail.port)
        
        return list(set(ports))  # Remove duplicates