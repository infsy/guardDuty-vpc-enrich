import json
import logging
import time
from typing import Dict, Any, List, Optional
from datetime import datetime

from guardduty_parser import GuardDutyFinding

logger = logging.getLogger(__name__)


class EnrichmentEngine:
    """Engine for enriching GuardDuty findings with VPC Flow Logs analysis."""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def enrich_finding(
        self,
        finding_data: GuardDutyFinding,
        flow_analysis: Optional[Dict[str, Any]],
        correlation_id: str
    ) -> Dict[str, Any]:
        """
        Enrich GuardDuty finding with VPC Flow Logs analysis.
        
        Args:
            finding_data: Parsed GuardDuty finding
            flow_analysis: VPC Flow Logs analysis results (can be None)
            correlation_id: Correlation ID for logging
            
        Returns:
            Dict containing enriched alert data
        """
        start_time = time.time()
        
        try:
            # Base enriched alert structure
            enriched_alert = self._create_base_alert(finding_data)
            
            # Add network context from flow logs
            if flow_analysis:
                enriched_alert["network_context"] = self._create_network_context(flow_analysis)
                
                # Enhance suspicious patterns with GuardDuty context
                enriched_alert["network_context"]["suspicious_patterns"] = self._enhance_suspicious_patterns(
                    flow_analysis.get("suspicious_patterns", []),
                    finding_data
                )
                
                # Add correlation insights
                enriched_alert["correlation_insights"] = self._generate_correlation_insights(
                    finding_data, flow_analysis
                )
            else:
                # No flow logs found
                enriched_alert["network_context"] = self._create_empty_network_context()
                enriched_alert["correlation_insights"] = {
                    "flow_logs_availability": "no_matching_logs",
                    "analysis_limitation": "Unable to perform network correlation due to missing VPC Flow Logs"
                }
            
            # Add analysis metadata
            processing_time = int((time.time() - start_time) * 1000)
            enriched_alert["analysis_metadata"] = self._create_analysis_metadata(
                processing_time, flow_analysis, correlation_id
            )
            
            # Add security recommendations
            enriched_alert["security_recommendations"] = self._generate_security_recommendations(
                finding_data, flow_analysis
            )
            
            self.logger.info(
                f"Successfully enriched finding {finding_data.finding_id}",
                extra={
                    "correlation_id": correlation_id,
                    "processing_time_ms": processing_time,
                    "flow_logs_available": flow_analysis is not None
                }
            )
            
            return enriched_alert
            
        except Exception as e:
            self.logger.error(
                f"Failed to enrich finding: {str(e)}",
                extra={"correlation_id": correlation_id},
                exc_info=True
            )
            # Return basic alert even if enrichment fails
            return self._create_base_alert(finding_data)
    
    def _create_base_alert(self, finding_data: GuardDutyFinding) -> Dict[str, Any]:
        """Create base alert structure from GuardDuty finding."""
        return {
            "finding_id": finding_data.finding_id,
            "severity": finding_data.severity,
            "finding_type": finding_data.finding_type,
            "timestamp": finding_data.timestamp.isoformat(),
            "title": finding_data.title,
            "description": finding_data.description,
            "region": finding_data.region,
            "account_id": finding_data.account_id,
            "resource": {
                "instance_id": finding_data.instance_id,
                "resource_type": finding_data.resource_type,
                "network_interfaces": [
                    {
                        "interface_id": eni.interface_id,
                        "private_ip": eni.private_ip,
                        "public_ip": eni.public_ip,
                        "vpc_id": eni.vpc_id,
                        "subnet_id": eni.subnet_id,
                        "security_groups": eni.security_groups
                    }
                    for eni in finding_data.network_interfaces
                ]
            },
            "threat_intelligence": {
                "remote_ips": [
                    {
                        "ip_address": ip.ip_address,
                        "country": ip.country,
                        "city": ip.city,
                        "organization": ip.organization,
                        "is_malicious": ip.is_malicious
                    }
                    for ip in finding_data.remote_ip_details
                ],
                "ports_involved": [
                    {
                        "port": port.port,
                        "port_name": port.port_name
                    }
                    for port in finding_data.port_details
                ]
            }
        }
    
    def _create_network_context(self, flow_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create network context from flow logs analysis."""
        return {
            "time_window": flow_analysis["time_window"],
            "traffic_summary": flow_analysis["traffic_summary"],
            "top_talkers": flow_analysis["top_talkers"],
            "suspicious_patterns": flow_analysis["suspicious_patterns"],
            "flow_logs_sample": flow_analysis.get("raw_flow_logs", [])
        }
    
    def _create_empty_network_context(self) -> Dict[str, Any]:
        """Create empty network context when no flow logs are available."""
        return {
            "time_window": None,
            "traffic_summary": {
                "total_connections": 0,
                "unique_remote_ips": 0,
                "total_bytes_in": 0,
                "total_bytes_out": 0,
                "rejected_connections": 0,
                "unique_ports": [],
                "protocol_distribution": {}
            },
            "top_talkers": [],
            "suspicious_patterns": [],
            "flow_logs_sample": []
        }
    
    def _enhance_suspicious_patterns(
        self,
        patterns: List[Dict[str, Any]],
        finding_data: GuardDutyFinding
    ) -> List[Dict[str, Any]]:
        """Enhance suspicious patterns with GuardDuty context."""
        enhanced_patterns = []
        
        for pattern in patterns:
            enhanced_pattern = pattern.copy()
            
            # Add severity assessment based on GuardDuty finding type
            enhanced_pattern["severity_assessment"] = self._assess_pattern_severity(
                pattern, finding_data
            )
            
            # Add context correlation
            enhanced_pattern["guardduty_correlation"] = self._correlate_with_guardduty(
                pattern, finding_data
            )
            
            enhanced_patterns.append(enhanced_pattern)
        
        # Add GuardDuty-specific patterns
        guardduty_patterns = self._generate_guardduty_specific_patterns(finding_data)
        enhanced_patterns.extend(guardduty_patterns)
        
        return enhanced_patterns
    
    def _assess_pattern_severity(
        self,
        pattern: Dict[str, Any],
        finding_data: GuardDutyFinding
    ) -> Dict[str, Any]:
        """Assess the severity of a suspicious pattern in context of GuardDuty finding."""
        base_severity = "medium"
        severity_factors = []
        
        # Pattern type severity mapping
        pattern_severity_map = {
            "port_scanning": "high",
            "data_exfiltration": "critical",
            "repeated_rejections": "medium",
            "unusual_time_activity": "low"
        }
        
        pattern_type = pattern.get("pattern_type", "unknown")
        base_severity = pattern_severity_map.get(pattern_type, "medium")
        
        # Adjust based on GuardDuty finding severity
        if finding_data.severity >= 7.0:
            severity_factors.append("high_guardduty_severity")
            if base_severity in ["medium", "low"]:
                base_severity = "high"
        
        # Adjust based on finding type
        high_risk_types = [
            "Backdoor:",
            "CryptoCurrency:",
            "Trojan:",
            "UnauthorizedAccess:"
        ]
        
        for risk_type in high_risk_types:
            if finding_data.finding_type.startswith(risk_type):
                severity_factors.append(f"high_risk_finding_type:{risk_type}")
                if base_severity == "low":
                    base_severity = "medium"
                break
        
        # Check for known malicious IPs
        for remote_ip in finding_data.remote_ip_details:
            if remote_ip.is_malicious:
                severity_factors.append("known_malicious_ip")
                if base_severity in ["low", "medium"]:
                    base_severity = "high"
        
        return {
            "level": base_severity,
            "factors": severity_factors,
            "confidence": self._calculate_confidence(pattern, finding_data)
        }
    
    def _calculate_confidence(
        self,
        pattern: Dict[str, Any],
        finding_data: GuardDutyFinding
    ) -> str:
        """Calculate confidence level for the pattern assessment."""
        confidence_score = 0
        
        # Base confidence from pattern evidence
        evidence = pattern.get("evidence", {})
        if isinstance(evidence, dict) and evidence:
            confidence_score += 30
        
        # Confidence from GuardDuty finding
        if finding_data.severity >= 6.0:
            confidence_score += 40
        elif finding_data.severity >= 4.0:
            confidence_score += 20
        
        # Confidence from network data availability
        if finding_data.network_interfaces:
            confidence_score += 20
        
        # Confidence from threat intelligence
        if any(ip.is_malicious for ip in finding_data.remote_ip_details):
            confidence_score += 30
        
        if confidence_score >= 80:
            return "high"
        elif confidence_score >= 50:
            return "medium"
        else:
            return "low"
    
    def _correlate_with_guardduty(
        self,
        pattern: Dict[str, Any],
        finding_data: GuardDutyFinding
    ) -> Dict[str, Any]:
        """Correlate flow log pattern with GuardDuty finding."""
        correlations = {
            "finding_type_relevance": "unknown",
            "timeline_correlation": "unknown",
            "asset_correlation": "unknown",
            "threat_correlation": "unknown"
        }
        
        pattern_type = pattern.get("pattern_type", "")
        
        # Finding type relevance
        if pattern_type == "port_scanning" and "Recon:" in finding_data.finding_type:
            correlations["finding_type_relevance"] = "high"
        elif pattern_type == "data_exfiltration" and "Exfiltration:" in finding_data.finding_type:
            correlations["finding_type_relevance"] = "high"
        elif pattern_type == "repeated_rejections" and "UnauthorizedAccess:" in finding_data.finding_type:
            correlations["finding_type_relevance"] = "medium"
        else:
            correlations["finding_type_relevance"] = "low"
        
        # Asset correlation
        if finding_data.instance_id and finding_data.network_interfaces:
            correlations["asset_correlation"] = "confirmed"
        else:
            correlations["asset_correlation"] = "partial"
        
        # Threat correlation
        if finding_data.remote_ip_details and any(ip.is_malicious for ip in finding_data.remote_ip_details):
            correlations["threat_correlation"] = "confirmed_malicious"
        elif finding_data.remote_ip_details:
            correlations["threat_correlation"] = "ip_identified"
        
        return correlations
    
    def _generate_guardduty_specific_patterns(
        self,
        finding_data: GuardDutyFinding
    ) -> List[Dict[str, Any]]:
        """Generate patterns specific to GuardDuty finding types."""
        patterns = []
        
        # Cryptocurrency mining pattern
        if "CryptoCurrency:" in finding_data.finding_type:
            patterns.append({
                "pattern_type": "cryptocurrency_mining",
                "description": "Potential cryptocurrency mining activity detected",
                "evidence": {
                    "finding_type": finding_data.finding_type,
                    "severity": finding_data.severity
                },
                "severity_assessment": {
                    "level": "high",
                    "factors": ["cryptocurrency_activity"],
                    "confidence": "high"
                },
                "guardduty_correlation": {
                    "finding_type_relevance": "high",
                    "asset_correlation": "confirmed",
                    "threat_correlation": "cryptocurrency_mining"
                }
            })
        
        # Backdoor communication pattern
        if "Backdoor:" in finding_data.finding_type:
            patterns.append({
                "pattern_type": "backdoor_communication",
                "description": "Potential backdoor communication detected",
                "evidence": {
                    "finding_type": finding_data.finding_type,
                    "remote_ips": [ip.ip_address for ip in finding_data.remote_ip_details]
                },
                "severity_assessment": {
                    "level": "critical",
                    "factors": ["backdoor_activity"],
                    "confidence": "high"
                },
                "guardduty_correlation": {
                    "finding_type_relevance": "high",
                    "asset_correlation": "confirmed",
                    "threat_correlation": "backdoor_communication"
                }
            })
        
        return patterns
    
    def _generate_correlation_insights(
        self,
        finding_data: GuardDutyFinding,
        flow_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate correlation insights between GuardDuty and flow logs."""
        insights = {
            "flow_logs_availability": "available",
            "correlation_quality": "unknown",
            "timeline_analysis": {},
            "network_behavior_analysis": {},
            "threat_validation": {}
        }
        
        # Timeline analysis
        time_window = flow_analysis.get("time_window", {})
        if time_window:
            insights["timeline_analysis"] = {
                "analysis_window": time_window,
                "finding_timestamp": finding_data.timestamp.isoformat(),
                "temporal_correlation": "within_analysis_window"
            }
        
        # Network behavior analysis
        traffic_summary = flow_analysis.get("traffic_summary", {})
        if traffic_summary.get("total_connections", 0) > 0:
            insights["network_behavior_analysis"] = {
                "activity_level": self._assess_activity_level(traffic_summary),
                "communication_patterns": self._analyze_communication_patterns(traffic_summary),
                "security_implications": self._assess_security_implications(traffic_summary, finding_data)
            }
        
        # Threat validation
        suspicious_patterns = flow_analysis.get("suspicious_patterns", [])
        insights["threat_validation"] = {
            "patterns_detected": len(suspicious_patterns),
            "validation_status": "confirmed" if suspicious_patterns else "no_additional_evidence",
            "confidence_level": "high" if len(suspicious_patterns) > 2 else "medium" if suspicious_patterns else "low"
        }
        
        # Overall correlation quality
        quality_factors = []
        if traffic_summary.get("total_connections", 0) > 10:
            quality_factors.append("sufficient_network_data")
        if suspicious_patterns:
            quality_factors.append("suspicious_patterns_detected")
        if finding_data.network_interfaces:
            quality_factors.append("network_interface_data_available")
        
        if len(quality_factors) >= 2:
            insights["correlation_quality"] = "high"
        elif quality_factors:
            insights["correlation_quality"] = "medium"
        else:
            insights["correlation_quality"] = "low"
        
        return insights
    
    def _assess_activity_level(self, traffic_summary: Dict[str, Any]) -> str:
        """Assess network activity level."""
        connections = traffic_summary.get("total_connections", 0)
        bytes_total = traffic_summary.get("total_bytes_in", 0) + traffic_summary.get("total_bytes_out", 0)
        
        if connections > 1000 or bytes_total > 100 * 1024 * 1024:  # > 100MB
            return "high"
        elif connections > 100 or bytes_total > 10 * 1024 * 1024:  # > 10MB
            return "medium"
        else:
            return "low"
    
    def _analyze_communication_patterns(self, traffic_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze communication patterns."""
        return {
            "unique_remote_ips": traffic_summary.get("unique_remote_ips", 0),
            "rejected_connection_ratio": (
                traffic_summary.get("rejected_connections", 0) / 
                max(traffic_summary.get("total_connections", 1), 1)
            ),
            "protocol_diversity": len(traffic_summary.get("protocol_distribution", {})),
            "port_diversity": len(traffic_summary.get("unique_ports", []))
        }
    
    def _assess_security_implications(
        self,
        traffic_summary: Dict[str, Any],
        finding_data: GuardDutyFinding
    ) -> List[str]:
        """Assess security implications of network behavior."""
        implications = []
        
        # High rejection rate
        if traffic_summary.get("rejected_connections", 0) > 50:
            implications.append("high_rejection_rate_indicates_blocked_attacks")
        
        # Large data transfers
        bytes_out = traffic_summary.get("total_bytes_out", 0)
        if bytes_out > 100 * 1024 * 1024:  # > 100MB outbound
            implications.append("large_outbound_transfer_potential_exfiltration")
        
        # Many unique IPs
        if traffic_summary.get("unique_remote_ips", 0) > 50:
            implications.append("communication_with_many_ips_potential_scanning")
        
        # Protocol anomalies
        protocols = traffic_summary.get("protocol_distribution", {})
        if len(protocols) > 5:
            implications.append("multiple_protocols_used_unusual_behavior")
        
        return implications
    
    def _generate_security_recommendations(
        self,
        finding_data: GuardDutyFinding,
        flow_analysis: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate security recommendations based on findings and flow analysis."""
        recommendations = []
        
        # Base recommendations from GuardDuty finding
        recommendations.extend(self._get_guardduty_recommendations(finding_data))
        
        # Additional recommendations from flow analysis
        if flow_analysis:
            recommendations.extend(self._get_flow_analysis_recommendations(flow_analysis, finding_data))
        
        # General security recommendations
        recommendations.extend(self._get_general_recommendations(finding_data))
        
        return recommendations
    
    def _get_guardduty_recommendations(self, finding_data: GuardDutyFinding) -> List[Dict[str, Any]]:
        """Get recommendations specific to GuardDuty finding type."""
        recommendations = []
        
        if "CryptoCurrency:" in finding_data.finding_type:
            recommendations.append({
                "category": "immediate_action",
                "priority": "high",
                "action": "Block cryptocurrency mining traffic",
                "description": "Implement network rules to block known cryptocurrency mining pools and protocols"
            })
        
        if "Backdoor:" in finding_data.finding_type:
            recommendations.append({
                "category": "immediate_action",
                "priority": "critical",
                "action": "Isolate affected instance",
                "description": "Immediately isolate the affected instance from the network to prevent lateral movement"
            })
        
        if "UnauthorizedAccess:" in finding_data.finding_type:
            recommendations.append({
                "category": "investigation",
                "priority": "high",
                "action": "Review access logs and credentials",
                "description": "Examine access logs, rotate credentials, and review IAM permissions"
            })
        
        return recommendations
    
    def _get_flow_analysis_recommendations(
        self,
        flow_analysis: Dict[str, Any],
        finding_data: GuardDutyFinding
    ) -> List[Dict[str, Any]]:
        """Get recommendations based on flow analysis results."""
        recommendations = []
        
        suspicious_patterns = flow_analysis.get("suspicious_patterns", [])
        
        for pattern in suspicious_patterns:
            pattern_type = pattern.get("pattern_type", "")
            
            if pattern_type == "port_scanning":
                recommendations.append({
                    "category": "network_security",
                    "priority": "medium",
                    "action": "Enhance port scanning detection",
                    "description": "Review and enhance network monitoring rules to detect port scanning activities"
                })
            
            elif pattern_type == "data_exfiltration":
                recommendations.append({
                    "category": "immediate_action",
                    "priority": "critical",
                    "action": "Investigate data exfiltration",
                    "description": "Immediately investigate potential data exfiltration and implement DLP controls"
                })
            
            elif pattern_type == "repeated_rejections":
                recommendations.append({
                    "category": "network_security",
                    "priority": "medium",
                    "action": "Review firewall rules",
                    "description": "Review and optimize firewall rules to ensure proper traffic filtering"
                })
        
        return recommendations
    
    def _get_general_recommendations(self, finding_data: GuardDutyFinding) -> List[Dict[str, Any]]:
        """Get general security recommendations."""
        return [
            {
                "category": "monitoring",
                "priority": "medium",
                "action": "Enable VPC Flow Logs",
                "description": "Ensure VPC Flow Logs are enabled for all subnets to improve security monitoring"
            },
            {
                "category": "incident_response",
                "priority": "medium",
                "action": "Document incident",
                "description": "Document this security incident in your incident response system for future reference"
            },
            {
                "category": "preventive",
                "priority": "low",
                "action": "Review security baselines",
                "description": "Review and update security baselines and monitoring rules based on this incident"
            }
        ]
    
    def _create_analysis_metadata(
        self,
        processing_time: int,
        flow_analysis: Optional[Dict[str, Any]],
        correlation_id: str
    ) -> Dict[str, Any]:
        """Create analysis metadata."""
        return {
            "processing_time_ms": processing_time,
            "correlation_id": correlation_id,
            "timestamp": datetime.utcnow().isoformat(),
            "logs_analyzed": flow_analysis.get("logs_analyzed", 0) if flow_analysis else 0,
            "data_sources": [
                "aws_guardduty",
                "vpc_flow_logs" if flow_analysis else None
            ],
            "analysis_version": "1.0",
            "enrichment_engine_version": "1.0"
        }