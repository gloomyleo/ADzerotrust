"""
Recommendation Engine - Generates actionable security recommendations for ADZero Trust
Provides prioritized recommendations based on assessment results and risk analysis

Author: Moazzam Jafri
"""

import logging
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class Priority(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class Category(Enum):
    IDENTITY = "Identity & Access Management"
    PERMISSIONS = "Least Privilege Access"
    SECURITY = "Security Configuration"
    INFRASTRUCTURE = "Infrastructure Security"
    MONITORING = "Monitoring & Analytics"
    COMPLIANCE = "Compliance & Governance"

@dataclass
class Recommendation:
    """Individual security recommendation"""
    id: str
    category: Category
    priority: Priority
    title: str
    description: str
    recommendation: str
    business_justification: str
    technical_details: str
    implementation_steps: List[str]
    estimated_effort: str
    estimated_timeline: str
    success_criteria: List[str]
    dependencies: List[str]
    risk_reduction: float
    compliance_frameworks: List[str]

class RecommendationEngine:
    """Generates prioritized security recommendations"""
    
    def __init__(self):
        self.recommendation_templates = self._load_recommendation_templates()
    
    def generate_recommendations(self, analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate prioritized recommendations based on analysis results
        
        Args:
            analysis_data: Complete analysis results including scores, risks, and gaps
            
        Returns:
            List of prioritized recommendations
        """
        logger.info("Generating security recommendations")
        
        try:
            recommendations = []
            
            # Generate identity recommendations
            identity_recs = self._generate_identity_recommendations(analysis_data)
            recommendations.extend(identity_recs)
            
            # Generate permission recommendations
            permission_recs = self._generate_permission_recommendations(analysis_data)
            recommendations.extend(permission_recs)
            
            # Generate security configuration recommendations
            security_recs = self._generate_security_recommendations(analysis_data)
            recommendations.extend(security_recs)
            
            # Generate infrastructure recommendations
            infrastructure_recs = self._generate_infrastructure_recommendations(analysis_data)
            recommendations.extend(infrastructure_recs)
            
            # Generate monitoring recommendations
            monitoring_recs = self._generate_monitoring_recommendations(analysis_data)
            recommendations.extend(monitoring_recs)
            
            # Generate compliance recommendations
            compliance_recs = self._generate_compliance_recommendations(analysis_data)
            recommendations.extend(compliance_recs)
            
            # Sort by priority and risk reduction
            prioritized_recs = self._prioritize_recommendations(recommendations)
            
            # Convert to dictionaries for API response
            return [self._recommendation_to_dict(rec) for rec in prioritized_recs]
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            raise
    
    def _generate_identity_recommendations(self, analysis_data: Dict[str, Any]) -> List[Recommendation]:
        """Generate identity and access management recommendations"""
        recommendations = []
        identity_analysis = analysis_data.get('identity_analysis', {})
        
        # MFA recommendations
        mfa_coverage = identity_analysis.get('mfa_coverage', 0)
        if mfa_coverage < 1.0:
            priority = Priority.CRITICAL if mfa_coverage < 0.5 else Priority.HIGH
            recommendations.append(Recommendation(
                id="IAM001",
                category=Category.IDENTITY,
                priority=priority,
                title="Implement Multi-Factor Authentication",
                description=f"Current MFA coverage is {mfa_coverage:.1%}. Implement MFA for all user accounts.",
                recommendation="Deploy MFA for all user accounts to prevent credential-based attacks",
                business_justification="MFA reduces the risk of account compromise by 99.9% according to Microsoft research",
                technical_details="Implement Azure MFA, ADFS with MFA, or third-party MFA solutions",
                implementation_steps=[
                    "Assess current MFA capabilities",
                    "Select appropriate MFA solution",
                    "Pilot MFA with administrative accounts",
                    "Roll out MFA to all users in phases",
                    "Provide user training and support",
                    "Monitor MFA adoption and compliance"
                ],
                estimated_effort="Medium",
                estimated_timeline="2-4 weeks",
                success_criteria=[
                    "100% MFA coverage for all accounts",
                    "Less than 5% MFA bypass requests",
                    "Reduced authentication-related incidents"
                ],
                dependencies=["MFA infrastructure", "User training program"],
                risk_reduction=85.0,
                compliance_frameworks=["NIST", "ISO 27001", "CIS Controls"]
            ))
        
        # Privileged account recommendations
        privileged_ratio = identity_analysis.get('privileged_ratio', 0)
        if privileged_ratio > 0.1:
            recommendations.append(Recommendation(
                id="IAM002",
                category=Category.IDENTITY,
                priority=Priority.HIGH,
                title="Reduce Privileged Account Count",
                description=f"{privileged_ratio:.1%} of accounts have privileged access. Implement privileged access management.",
                recommendation="Implement just-in-time privileged access and reduce standing privileges",
                business_justification="Reduces insider threat risk and limits blast radius of compromised accounts",
                technical_details="Implement Azure PIM, CyberArk, or similar PAM solution",
                implementation_steps=[
                    "Audit all privileged accounts",
                    "Identify accounts that don't need standing privileges",
                    "Implement just-in-time access",
                    "Set up privileged access workflows",
                    "Monitor privileged access usage",
                    "Regular privileged access reviews"
                ],
                estimated_effort="High",
                estimated_timeline="4-8 weeks",
                success_criteria=[
                    "Less than 5% of accounts with standing privileges",
                    "100% of privileged access requests logged",
                    "Regular privileged access reviews completed"
                ],
                dependencies=["PAM solution", "Approval workflows"],
                risk_reduction=70.0,
                compliance_frameworks=["NIST", "ISO 27001", "SOX"]
            ))
        
        return recommendations
    
    def _generate_permission_recommendations(self, analysis_data: Dict[str, Any]) -> List[Recommendation]:
        """Generate permission and access control recommendations"""
        recommendations = []
        permission_analysis = analysis_data.get('permission_analysis', {})
        
        # Excessive permissions
        excessive_ratio = permission_analysis.get('excessive_ratio', 0)
        if excessive_ratio > 0.1:
            priority = Priority.HIGH if excessive_ratio > 0.2 else Priority.MEDIUM
            recommendations.append(Recommendation(
                id="PAC001",
                category=Category.PERMISSIONS,
                priority=priority,
                title="Remove Excessive Permissions",
                description=f"{excessive_ratio:.1%} of permissions are excessive. Implement least privilege access.",
                recommendation="Conduct comprehensive permission review and remove unnecessary access rights",
                business_justification="Reduces attack surface and limits potential damage from compromised accounts",
                technical_details="Use access review tools and implement role-based access control",
                implementation_steps=[
                    "Inventory all current permissions",
                    "Identify excessive or unused permissions",
                    "Implement role-based access model",
                    "Remove unnecessary permissions",
                    "Establish regular access reviews",
                    "Monitor permission changes"
                ],
                estimated_effort="High",
                estimated_timeline="6-12 weeks",
                success_criteria=[
                    "Less than 5% excessive permissions",
                    "Quarterly access reviews completed",
                    "Role-based access model implemented"
                ],
                dependencies=["Access review tools", "Business process owners"],
                risk_reduction=60.0,
                compliance_frameworks=["NIST", "ISO 27001", "SOX", "GDPR"]
            ))
        
        return recommendations
    
    def _generate_security_recommendations(self, analysis_data: Dict[str, Any]) -> List[Recommendation]:
        """Generate security configuration recommendations"""
        recommendations = []
        security_analysis = analysis_data.get('security_analysis', {})
        
        # Policy compliance
        policy_compliance = security_analysis.get('policy_compliance_ratio', 1)
        if policy_compliance < 0.9:
            recommendations.append(Recommendation(
                id="SEC001",
                category=Category.SECURITY,
                priority=Priority.MEDIUM,
                title="Update Security Policies",
                description=f"Security policy compliance is {policy_compliance:.1%}. Update non-compliant policies.",
                recommendation="Review and update all security policies to ensure compliance",
                business_justification="Consistent security policies reduce risk and ensure regulatory compliance",
                technical_details="Update Group Policy Objects and security baselines",
                implementation_steps=[
                    "Audit current security policies",
                    "Identify non-compliant policies",
                    "Update policies to meet security standards",
                    "Test policy changes in staging",
                    "Deploy updated policies",
                    "Monitor policy compliance"
                ],
                estimated_effort="Medium",
                estimated_timeline="3-6 weeks",
                success_criteria=[
                    "100% policy compliance",
                    "Regular policy reviews scheduled",
                    "Policy exceptions documented and approved"
                ],
                dependencies=["Security baselines", "Change management process"],
                risk_reduction=40.0,
                compliance_frameworks=["NIST", "ISO 27001", "CIS Controls"]
            ))
        
        return recommendations
    
    def _generate_infrastructure_recommendations(self, analysis_data: Dict[str, Any]) -> List[Recommendation]:
        """Generate infrastructure security recommendations"""
        recommendations = []
        infrastructure_analysis = analysis_data.get('infrastructure_analysis', {})
        
        # Network segmentation
        segmentation_score = infrastructure_analysis.get('segmentation_score', 1)
        if segmentation_score < 0.8:
            recommendations.append(Recommendation(
                id="INF001",
                category=Category.INFRASTRUCTURE,
                priority=Priority.HIGH,
                title="Implement Network Segmentation",
                description=f"Network segmentation score is {segmentation_score:.1%}. Implement micro-segmentation.",
                recommendation="Deploy network micro-segmentation to limit lateral movement",
                business_justification="Prevents lateral movement and contains security breaches",
                technical_details="Implement software-defined perimeter or network access control",
                implementation_steps=[
                    "Map current network topology",
                    "Design segmentation strategy",
                    "Implement network access controls",
                    "Deploy micro-segmentation solution",
                    "Test network connectivity",
                    "Monitor network traffic patterns"
                ],
                estimated_effort="High",
                estimated_timeline="8-16 weeks",
                success_criteria=[
                    "Network segments isolated appropriately",
                    "Reduced east-west traffic",
                    "Network access controls enforced"
                ],
                dependencies=["Network infrastructure", "Security tools"],
                risk_reduction=75.0,
                compliance_frameworks=["NIST", "ISO 27001"]
            ))
        
        return recommendations
    
    def _generate_monitoring_recommendations(self, analysis_data: Dict[str, Any]) -> List[Recommendation]:
        """Generate monitoring and analytics recommendations"""
        recommendations = []
        security_analysis = analysis_data.get('security_analysis', {})
        
        # Audit logging
        if not security_analysis.get('audit_enabled', True):
            recommendations.append(Recommendation(
                id="MON001",
                category=Category.MONITORING,
                priority=Priority.CRITICAL,
                title="Enable Comprehensive Audit Logging",
                description="Audit logging is not enabled. Enable comprehensive security event logging.",
                recommendation="Implement comprehensive audit logging and SIEM integration",
                business_justification="Essential for threat detection, incident response, and compliance",
                technical_details="Configure Windows audit policies and deploy SIEM solution",
                implementation_steps=[
                    "Configure audit policies on domain controllers",
                    "Enable security event logging",
                    "Deploy SIEM or log management solution",
                    "Configure log forwarding",
                    "Set up security alerts and dashboards",
                    "Establish log retention policies"
                ],
                estimated_effort="Medium",
                estimated_timeline="4-8 weeks",
                success_criteria=[
                    "All security events logged",
                    "SIEM solution operational",
                    "Security alerts configured"
                ],
                dependencies=["SIEM solution", "Log storage infrastructure"],
                risk_reduction=80.0,
                compliance_frameworks=["NIST", "ISO 27001", "PCI DSS", "SOX"]
            ))
        
        return recommendations
    
    def _generate_compliance_recommendations(self, analysis_data: Dict[str, Any]) -> List[Recommendation]:
        """Generate compliance and governance recommendations"""
        recommendations = []
        
        # General compliance recommendation
        recommendations.append(Recommendation(
            id="COM001",
            category=Category.COMPLIANCE,
            priority=Priority.MEDIUM,
            title="Establish Zero Trust Governance",
            description="Implement governance framework for Zero Trust implementation",
            recommendation="Establish Zero Trust governance committee and processes",
            business_justification="Ensures successful Zero Trust implementation and ongoing compliance",
            technical_details="Create governance framework, policies, and procedures",
            implementation_steps=[
                "Form Zero Trust governance committee",
                "Develop Zero Trust policies and procedures",
                "Establish compliance monitoring processes",
                "Create Zero Trust training program",
                "Implement regular compliance assessments",
                "Establish continuous improvement process"
            ],
            estimated_effort="Medium",
            estimated_timeline="6-12 weeks",
            success_criteria=[
                "Governance committee established",
                "Zero Trust policies approved",
                "Regular compliance assessments scheduled"
            ],
            dependencies=["Executive sponsorship", "Policy framework"],
            risk_reduction=30.0,
            compliance_frameworks=["NIST", "ISO 27001", "COBIT"]
        ))
        
        return recommendations
    
    def _prioritize_recommendations(self, recommendations: List[Recommendation]) -> List[Recommendation]:
        """Prioritize recommendations based on priority, risk reduction, and effort"""
        priority_weights = {
            Priority.CRITICAL: 4,
            Priority.HIGH: 3,
            Priority.MEDIUM: 2,
            Priority.LOW: 1
        }
        
        def priority_score(rec):
            return (
                priority_weights[rec.priority] * 100 +
                rec.risk_reduction +
                (50 if rec.estimated_effort == "Low" else 
                 30 if rec.estimated_effort == "Medium" else 10)
            )
        
        return sorted(recommendations, key=priority_score, reverse=True)
    
    def _recommendation_to_dict(self, rec: Recommendation) -> Dict[str, Any]:
        """Convert Recommendation to dictionary"""
        return {
            'id': rec.id,
            'category': rec.category.value,
            'priority': rec.priority.value,
            'title': rec.title,
            'description': rec.description,
            'recommendation': rec.recommendation,
            'business_justification': rec.business_justification,
            'technical_details': rec.technical_details,
            'implementation_steps': rec.implementation_steps,
            'estimated_effort': rec.estimated_effort,
            'estimated_timeline': rec.estimated_timeline,
            'success_criteria': rec.success_criteria,
            'dependencies': rec.dependencies,
            'risk_reduction': rec.risk_reduction,
            'compliance_frameworks': rec.compliance_frameworks
        }
    
    def _load_recommendation_templates(self) -> Dict[str, Any]:
        """Load recommendation templates (placeholder for future enhancement)"""
        return {}

