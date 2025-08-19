"""
Risk Calculator - Comprehensive risk assessment for ADZero Trust
Calculates identity risks, permission risks, and overall security risks

Author: Moazzam Jafri
"""

import logging
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class RiskItem:
    """Individual risk item"""
    id: str
    type: str  # 'identity', 'permission', 'configuration', 'infrastructure'
    name: str
    description: str
    risk_level: RiskLevel
    risk_score: float
    impact: str
    likelihood: str
    mitigation: str
    affected_resources: List[str]
    detection_date: str

class RiskCalculator:
    """Comprehensive risk assessment engine"""
    
    def __init__(self):
        # Risk scoring weights
        self.risk_weights = {
            'identity_risks': 0.35,
            'permission_risks': 0.30,
            'configuration_risks': 0.20,
            'infrastructure_risks': 0.15
        }
        
        # Risk level thresholds
        self.risk_thresholds = {
            RiskLevel.LOW: (0, 25),
            RiskLevel.MEDIUM: (25, 50),
            RiskLevel.HIGH: (50, 75),
            RiskLevel.CRITICAL: (75, 100)
        }
    
    def calculate_comprehensive_risk(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate comprehensive risk assessment
        
        Args:
            analysis_data: Complete analysis data from zero trust analyzer
            
        Returns:
            Dict containing comprehensive risk summary
        """
        logger.info("Calculating comprehensive risk assessment")
        
        try:
            # Calculate individual risk categories
            identity_risks = self._calculate_identity_risks(analysis_data.get('identity_analysis', {}))
            permission_risks = self._calculate_permission_risks(analysis_data.get('permission_analysis', {}))
            configuration_risks = self._calculate_configuration_risks(analysis_data.get('security_analysis', {}))
            infrastructure_risks = self._calculate_infrastructure_risks(analysis_data.get('infrastructure_analysis', {}))
            
            # Calculate overall risk score
            overall_risk_score = self._calculate_overall_risk_score({
                'identity_risks': identity_risks,
                'permission_risks': permission_risks,
                'configuration_risks': configuration_risks,
                'infrastructure_risks': infrastructure_risks
            })
            
            # Determine overall risk level
            overall_risk_level = self._determine_risk_level(overall_risk_score)
            
            # Identify top risks
            all_risks = (identity_risks['risk_items'] + 
                        permission_risks['risk_items'] + 
                        configuration_risks['risk_items'] + 
                        infrastructure_risks['risk_items'])
            
            top_risks = sorted(all_risks, key=lambda x: x.risk_score, reverse=True)[:10]
            
            # Generate risk trends (simulated for now)
            risk_trends = self._generate_risk_trends(overall_risk_score)
            
            return {
                'overall_risk_score': overall_risk_score,
                'overall_risk_level': overall_risk_level.value,
                'identity_risks': identity_risks,
                'permission_risks': permission_risks,
                'configuration_risks': configuration_risks,
                'infrastructure_risks': infrastructure_risks,
                'top_risks': [self._risk_item_to_dict(risk) for risk in top_risks],
                'risk_distribution': self._calculate_risk_distribution(all_risks),
                'risk_trends': risk_trends,
                'mitigation_priority': self._calculate_mitigation_priority(all_risks)
            }
            
        except Exception as e:
            logger.error(f"Error calculating comprehensive risk: {str(e)}")
            raise
    
    def _calculate_identity_risks(self, identity_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate identity-related risks"""
        risk_items = []
        
        # MFA coverage risk
        mfa_coverage = identity_analysis.get('mfa_coverage', 0)
        if mfa_coverage < 0.5:
            risk_items.append(RiskItem(
                id="ID001",
                type="identity",
                name="Low MFA Coverage",
                description=f"Only {mfa_coverage:.1%} of users have MFA enabled",
                risk_level=RiskLevel.HIGH,
                risk_score=85 - (mfa_coverage * 50),
                impact="High - Credential-based attacks",
                likelihood="High - Common attack vector",
                mitigation="Implement MFA for all user accounts",
                affected_resources=[f"{identity_analysis.get('human_identities', 0)} user accounts"],
                detection_date="Current assessment"
            ))
        elif mfa_coverage < 0.8:
            risk_items.append(RiskItem(
                id="ID002",
                type="identity",
                name="Partial MFA Coverage",
                description=f"{mfa_coverage:.1%} of users have MFA enabled",
                risk_level=RiskLevel.MEDIUM,
                risk_score=50 - (mfa_coverage * 25),
                impact="Medium - Some accounts vulnerable",
                likelihood="Medium - Targeted attacks",
                mitigation="Expand MFA coverage to all users",
                affected_resources=[f"{int(identity_analysis.get('human_identities', 0) * (1-mfa_coverage))} unprotected accounts"],
                detection_date="Current assessment"
            ))
        
        # Privileged account risk
        privileged_ratio = identity_analysis.get('privileged_ratio', 0)
        if privileged_ratio > 0.15:
            risk_items.append(RiskItem(
                id="ID003",
                type="identity",
                name="Excessive Privileged Accounts",
                description=f"{privileged_ratio:.1%} of accounts have privileged access",
                risk_level=RiskLevel.HIGH,
                risk_score=60 + (privileged_ratio * 100),
                impact="High - Privilege escalation risk",
                likelihood="Medium - Internal threats",
                mitigation="Review and reduce privileged account count",
                affected_resources=[f"{identity_analysis.get('privileged_accounts', 0)} privileged accounts"],
                detection_date="Current assessment"
            ))
        
        # Password strength risk
        password_score = identity_analysis.get('password_score', 1)
        if password_score < 0.7:
            risk_items.append(RiskItem(
                id="ID004",
                type="identity",
                name="Weak Password Policies",
                description=f"Password strength score: {password_score:.1%}",
                risk_level=RiskLevel.MEDIUM,
                risk_score=70 - (password_score * 40),
                impact="Medium - Password-based attacks",
                likelihood="High - Common attack method",
                mitigation="Enforce strong password policies",
                affected_resources=["All user accounts"],
                detection_date="Current assessment"
            ))
        
        # High-risk identities
        high_risk_identities = identity_analysis.get('high_risk_identities', [])
        if high_risk_identities:
            risk_items.append(RiskItem(
                id="ID005",
                type="identity",
                name="High-Risk Identity Accounts",
                description=f"{len(high_risk_identities)} accounts flagged as high-risk",
                risk_level=RiskLevel.HIGH,
                risk_score=75,
                impact="High - Compromised accounts",
                likelihood="Medium - Targeted attacks",
                mitigation="Review and secure high-risk accounts",
                affected_resources=[identity.get('name', 'Unknown') for identity in high_risk_identities[:5]],
                detection_date="Current assessment"
            ))
        
        # Calculate category risk score
        category_risk_score = sum(item.risk_score for item in risk_items) / max(len(risk_items), 1)
        category_risk_level = self._determine_risk_level(category_risk_score)
        
        return {
            'category': 'Identity Risks',
            'risk_score': category_risk_score,
            'risk_level': category_risk_level.value,
            'total_risks': len(risk_items),
            'high_risks': len([r for r in risk_items if r.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]),
            'risk_items': risk_items
        }
    
    def _calculate_permission_risks(self, permission_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate permission-related risks"""
        risk_items = []
        
        # Excessive permissions risk
        excessive_ratio = permission_analysis.get('excessive_ratio', 0)
        if excessive_ratio > 0.2:
            risk_items.append(RiskItem(
                id="PR001",
                type="permission",
                name="Excessive Permissions",
                description=f"{excessive_ratio:.1%} of permissions are excessive",
                risk_level=RiskLevel.HIGH,
                risk_score=60 + (excessive_ratio * 100),
                impact="High - Privilege escalation",
                likelihood="Medium - Insider threats",
                mitigation="Review and remove excessive permissions",
                affected_resources=[f"{permission_analysis.get('excessive_permissions', 0)} excessive permissions"],
                detection_date="Current assessment"
            ))
        elif excessive_ratio > 0.1:
            risk_items.append(RiskItem(
                id="PR002",
                type="permission",
                name="Some Excessive Permissions",
                description=f"{excessive_ratio:.1%} of permissions are excessive",
                risk_level=RiskLevel.MEDIUM,
                risk_score=40 + (excessive_ratio * 50),
                impact="Medium - Limited privilege escalation",
                likelihood="Low - Requires specific knowledge",
                mitigation="Regular permission reviews",
                affected_resources=[f"{permission_analysis.get('excessive_permissions', 0)} excessive permissions"],
                detection_date="Current assessment"
            ))
        
        # Large groups risk
        large_groups = permission_analysis.get('large_groups', 0)
        if large_groups > 5:
            risk_items.append(RiskItem(
                id="PR003",
                type="permission",
                name="Large Security Groups",
                description=f"{large_groups} groups with >50 members",
                risk_level=RiskLevel.MEDIUM,
                risk_score=45 + (large_groups * 5),
                impact="Medium - Broad access exposure",
                likelihood="Medium - Group-based attacks",
                mitigation="Break down large groups into smaller, role-based groups",
                affected_resources=[f"{large_groups} large groups"],
                detection_date="Current assessment"
            ))
        
        # Administrative groups risk
        admin_groups = permission_analysis.get('admin_groups', 0)
        if admin_groups > 5:
            risk_items.append(RiskItem(
                id="PR004",
                type="permission",
                name="Multiple Administrative Groups",
                description=f"{admin_groups} administrative groups detected",
                risk_level=RiskLevel.MEDIUM,
                risk_score=50 + (admin_groups * 3),
                impact="Medium - Administrative access sprawl",
                likelihood="Medium - Privilege abuse",
                mitigation="Consolidate administrative groups",
                affected_resources=[f"{admin_groups} admin groups"],
                detection_date="Current assessment"
            ))
        
        # High-risk permissions
        high_risk_permissions = permission_analysis.get('high_risk_permissions', [])
        if high_risk_permissions:
            risk_items.append(RiskItem(
                id="PR005",
                type="permission",
                name="High-Risk Permissions",
                description=f"{len(high_risk_permissions)} high-risk permissions identified",
                risk_level=RiskLevel.HIGH,
                risk_score=70,
                impact="High - Critical system access",
                likelihood="Medium - Targeted exploitation",
                mitigation="Review and restrict high-risk permissions",
                affected_resources=[perm.get('resource', 'Unknown') for perm in high_risk_permissions[:5]],
                detection_date="Current assessment"
            ))
        
        # Calculate category risk score
        category_risk_score = sum(item.risk_score for item in risk_items) / max(len(risk_items), 1)
        category_risk_level = self._determine_risk_level(category_risk_score)
        
        return {
            'category': 'Permission Risks',
            'risk_score': category_risk_score,
            'risk_level': category_risk_level.value,
            'total_risks': len(risk_items),
            'high_risks': len([r for r in risk_items if r.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]),
            'risk_items': risk_items
        }
    
    def _calculate_configuration_risks(self, security_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate configuration-related risks"""
        risk_items = []
        
        # Policy compliance risk
        policy_compliance = security_analysis.get('policy_compliance_ratio', 1)
        if policy_compliance < 0.8:
            risk_items.append(RiskItem(
                id="CR001",
                type="configuration",
                name="Non-Compliant Security Policies",
                description=f"{policy_compliance:.1%} policy compliance rate",
                risk_level=RiskLevel.MEDIUM,
                risk_score=60 - (policy_compliance * 30),
                impact="Medium - Inconsistent security posture",
                likelihood="Medium - Configuration drift",
                mitigation="Update and enforce security policies",
                affected_resources=[f"{security_analysis.get('total_policies', 0) - security_analysis.get('compliant_policies', 0)} non-compliant policies"],
                detection_date="Current assessment"
            ))
        
        # Audit configuration risk
        if not security_analysis.get('audit_enabled', True):
            risk_items.append(RiskItem(
                id="CR002",
                type="configuration",
                name="Audit Logging Disabled",
                description="Security audit logging is not enabled",
                risk_level=RiskLevel.HIGH,
                risk_score=80,
                impact="High - No visibility into security events",
                likelihood="High - Blind spots in monitoring",
                mitigation="Enable comprehensive audit logging",
                affected_resources=["All domain controllers"],
                detection_date="Current assessment"
            ))
        elif not security_analysis.get('audit_comprehensive', True):
            risk_items.append(RiskItem(
                id="CR003",
                type="configuration",
                name="Limited Audit Coverage",
                description="Audit logging is not comprehensive",
                risk_level=RiskLevel.MEDIUM,
                risk_score=50,
                impact="Medium - Limited security visibility",
                likelihood="Medium - Partial monitoring gaps",
                mitigation="Expand audit logging coverage",
                affected_resources=["Domain audit configuration"],
                detection_date="Current assessment"
            ))
        
        # Encryption risk
        encryption_score = security_analysis.get('encryption_score', 1)
        if encryption_score < 0.7:
            risk_items.append(RiskItem(
                id="CR004",
                type="configuration",
                name="Insufficient Data Encryption",
                description=f"Encryption score: {encryption_score:.1%}",
                risk_level=RiskLevel.HIGH,
                risk_score=75 - (encryption_score * 25),
                impact="High - Data exposure risk",
                likelihood="Medium - Data interception",
                mitigation="Implement comprehensive data encryption",
                affected_resources=["Sensitive data stores"],
                detection_date="Current assessment"
            ))
        
        # Calculate category risk score
        category_risk_score = sum(item.risk_score for item in risk_items) / max(len(risk_items), 1)
        category_risk_level = self._determine_risk_level(category_risk_score)
        
        return {
            'category': 'Configuration Risks',
            'risk_score': category_risk_score,
            'risk_level': category_risk_level.value,
            'total_risks': len(risk_items),
            'high_risks': len([r for r in risk_items if r.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]),
            'risk_items': risk_items
        }
    
    def _calculate_infrastructure_risks(self, infrastructure_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate infrastructure-related risks"""
        risk_items = []
        
        # Network segmentation risk
        segmentation_score = infrastructure_analysis.get('segmentation_score', 1)
        if segmentation_score < 0.6:
            risk_items.append(RiskItem(
                id="IR001",
                type="infrastructure",
                name="Poor Network Segmentation",
                description=f"Network segmentation score: {segmentation_score:.1%}",
                risk_level=RiskLevel.HIGH,
                risk_score=70 - (segmentation_score * 30),
                impact="High - Lateral movement risk",
                likelihood="High - Network-based attacks",
                mitigation="Implement network micro-segmentation",
                affected_resources=[f"{infrastructure_analysis.get('network_segments', 0)} network segments"],
                detection_date="Current assessment"
            ))
        
        # Device compliance risk
        device_compliance = infrastructure_analysis.get('device_compliance_score', 1)
        if device_compliance < 0.8:
            risk_items.append(RiskItem(
                id="IR002",
                type="infrastructure",
                name="Non-Compliant Devices",
                description=f"Device compliance score: {device_compliance:.1%}",
                risk_level=RiskLevel.MEDIUM,
                risk_score=55 - (device_compliance * 25),
                impact="Medium - Device-based attacks",
                likelihood="Medium - Endpoint vulnerabilities",
                mitigation="Enforce device compliance policies",
                affected_resources=[f"{infrastructure_analysis.get('total_devices', 0) - infrastructure_analysis.get('compliant_devices', 0)} non-compliant devices"],
                detection_date="Current assessment"
            ))
        
        # Application security risk
        app_security_score = infrastructure_analysis.get('app_security_score', 1)
        if app_security_score < 0.7:
            risk_items.append(RiskItem(
                id="IR003",
                type="infrastructure",
                name="Insecure Applications",
                description=f"Application security score: {app_security_score:.1%}",
                risk_level=RiskLevel.MEDIUM,
                risk_score=60 - (app_security_score * 30),
                impact="Medium - Application vulnerabilities",
                likelihood="Medium - Application-based attacks",
                mitigation="Implement application security controls",
                affected_resources=[f"{infrastructure_analysis.get('total_applications', 0) - infrastructure_analysis.get('secure_applications', 0)} insecure applications"],
                detection_date="Current assessment"
            ))
        
        # Calculate category risk score
        category_risk_score = sum(item.risk_score for item in risk_items) / max(len(risk_items), 1)
        category_risk_level = self._determine_risk_level(category_risk_score)
        
        return {
            'category': 'Infrastructure Risks',
            'risk_score': category_risk_score,
            'risk_level': category_risk_level.value,
            'total_risks': len(risk_items),
            'high_risks': len([r for r in risk_items if r.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]),
            'risk_items': risk_items
        }
    
    def _calculate_overall_risk_score(self, risk_categories: Dict[str, Any]) -> float:
        """Calculate overall risk score from all categories"""
        weighted_score = (
            risk_categories['identity_risks']['risk_score'] * self.risk_weights['identity_risks'] +
            risk_categories['permission_risks']['risk_score'] * self.risk_weights['permission_risks'] +
            risk_categories['configuration_risks']['risk_score'] * self.risk_weights['configuration_risks'] +
            risk_categories['infrastructure_risks']['risk_score'] * self.risk_weights['infrastructure_risks']
        )
        
        return round(weighted_score, 1)
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level based on score"""
        for level, (min_score, max_score) in self.risk_thresholds.items():
            if min_score <= risk_score < max_score:
                return level
        return RiskLevel.CRITICAL  # For scores >= 75
    
    def _calculate_risk_distribution(self, all_risks: List[RiskItem]) -> Dict[str, int]:
        """Calculate distribution of risks by level"""
        distribution = {level.value: 0 for level in RiskLevel}
        
        for risk in all_risks:
            distribution[risk.risk_level.value] += 1
        
        return distribution
    
    def _generate_risk_trends(self, current_score: float) -> Dict[str, Any]:
        """Generate risk trend data (simulated for demonstration)"""
        # In a real implementation, this would pull historical data
        return {
            'current_score': current_score,
            'trend': 'improving',  # 'improving', 'stable', 'degrading'
            'monthly_scores': [
                {'month': 'Jan', 'score': current_score + 5},
                {'month': 'Feb', 'score': current_score + 3},
                {'month': 'Mar', 'score': current_score}
            ],
            'risk_velocity': -2.5  # Negative means improving
        }
    
    def _calculate_mitigation_priority(self, all_risks: List[RiskItem]) -> List[Dict[str, Any]]:
        """Calculate mitigation priority based on risk score and impact"""
        priority_risks = sorted(all_risks, key=lambda x: x.risk_score, reverse=True)[:5]
        
        return [
            {
                'rank': i + 1,
                'risk_id': risk.id,
                'name': risk.name,
                'risk_score': risk.risk_score,
                'risk_level': risk.risk_level.value,
                'mitigation': risk.mitigation,
                'estimated_effort': self._estimate_mitigation_effort(risk),
                'business_impact': self._estimate_business_impact(risk)
            }
            for i, risk in enumerate(priority_risks)
        ]
    
    def _estimate_mitigation_effort(self, risk: RiskItem) -> str:
        """Estimate effort required for mitigation"""
        if risk.risk_score > 70:
            return "High"
        elif risk.risk_score > 40:
            return "Medium"
        else:
            return "Low"
    
    def _estimate_business_impact(self, risk: RiskItem) -> str:
        """Estimate business impact of the risk"""
        if risk.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return "High"
        elif risk.risk_level == RiskLevel.MEDIUM:
            return "Medium"
        else:
            return "Low"
    
    def _risk_item_to_dict(self, risk: RiskItem) -> Dict[str, Any]:
        """Convert RiskItem to dictionary"""
        return {
            'id': risk.id,
            'type': risk.type,
            'name': risk.name,
            'description': risk.description,
            'risk_level': risk.risk_level.value,
            'risk_score': risk.risk_score,
            'impact': risk.impact,
            'likelihood': risk.likelihood,
            'mitigation': risk.mitigation,
            'affected_resources': risk.affected_resources,
            'detection_date': risk.detection_date
        }

