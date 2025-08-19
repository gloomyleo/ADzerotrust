"""
Zero Trust Analyzer - Main analysis engine for ADZero Trust
Coordinates all analysis components to provide comprehensive zero trust assessment

Author: Moazzam Jafri
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

from .risk_calculator import RiskCalculator
from .recommendation_engine import RecommendationEngine
from .maturity_assessor import MaturityAssessor
from .compliance_checker import ComplianceChecker

logger = logging.getLogger(__name__)

@dataclass
class ZeroTrustAssessmentResult:
    """Complete zero trust assessment result"""
    assessment_id: str
    domain: str
    timestamp: datetime
    overall_score: float
    maturity_level: str
    risk_summary: Dict[str, Any]
    recommendations: List[Dict[str, Any]]
    compliance_status: Dict[str, Any]
    identity_analysis: Dict[str, Any]
    permission_analysis: Dict[str, Any]
    security_gaps: List[Dict[str, Any]]
    implementation_roadmap: Dict[str, Any]

class ZeroTrustAnalyzer:
    """Main Zero Trust analysis engine"""
    
    def __init__(self):
        self.risk_calculator = RiskCalculator()
        self.recommendation_engine = RecommendationEngine()
        self.maturity_assessor = MaturityAssessor()
        self.compliance_checker = ComplianceChecker()
        
        # Zero Trust scoring weights
        self.scoring_weights = {
            'identity_verification': 0.25,
            'device_compliance': 0.20,
            'network_segmentation': 0.15,
            'data_protection': 0.15,
            'application_security': 0.15,
            'monitoring_analytics': 0.10
        }
        
        # Maturity level thresholds
        self.maturity_thresholds = {
            'traditional': (0, 30),
            'initial': (30, 50),
            'intermediate': (50, 75),
            'advanced': (75, 100)
        }
    
    def analyze_assessment(self, assessment_data: Dict[str, Any]) -> ZeroTrustAssessmentResult:
        """
        Perform comprehensive zero trust analysis on assessment data
        
        Args:
            assessment_data: Raw assessment data from PowerShell scripts
            
        Returns:
            ZeroTrustAssessmentResult: Complete analysis results
        """
        logger.info(f"Starting zero trust analysis for assessment {assessment_data.get('id')}")
        
        try:
            # Extract key components
            identity_data = assessment_data.get('identities', {})
            permission_data = assessment_data.get('permissions', {})
            security_data = assessment_data.get('security_config', {})
            infrastructure_data = assessment_data.get('infrastructure', {})
            
            # Perform individual analyses
            identity_analysis = self._analyze_identities(identity_data)
            permission_analysis = self._analyze_permissions(permission_data)
            security_analysis = self._analyze_security_config(security_data)
            infrastructure_analysis = self._analyze_infrastructure(infrastructure_data)
            
            # Calculate overall zero trust score
            overall_score = self._calculate_overall_score({
                'identity': identity_analysis,
                'permissions': permission_analysis,
                'security': security_analysis,
                'infrastructure': infrastructure_analysis
            })
            
            # Determine maturity level
            maturity_level = self._determine_maturity_level(overall_score)
            
            # Calculate risks
            risk_summary = self.risk_calculator.calculate_comprehensive_risk({
                'identity_analysis': identity_analysis,
                'permission_analysis': permission_analysis,
                'security_analysis': security_analysis,
                'infrastructure_analysis': infrastructure_analysis
            })
            
            # Generate recommendations
            recommendations = self.recommendation_engine.generate_recommendations({
                'score': overall_score,
                'maturity_level': maturity_level,
                'risk_summary': risk_summary,
                'identity_analysis': identity_analysis,
                'permission_analysis': permission_analysis,
                'security_analysis': security_analysis
            })
            
            # Check compliance
            compliance_status = self.compliance_checker.check_compliance({
                'identity_analysis': identity_analysis,
                'permission_analysis': permission_analysis,
                'security_analysis': security_analysis
            })
            
            # Identify security gaps
            security_gaps = self._identify_security_gaps({
                'identity_analysis': identity_analysis,
                'permission_analysis': permission_analysis,
                'security_analysis': security_analysis,
                'infrastructure_analysis': infrastructure_analysis
            })
            
            # Generate implementation roadmap
            implementation_roadmap = self._generate_implementation_roadmap({
                'current_score': overall_score,
                'maturity_level': maturity_level,
                'recommendations': recommendations,
                'security_gaps': security_gaps
            })
            
            # Create final result
            result = ZeroTrustAssessmentResult(
                assessment_id=assessment_data.get('id', ''),
                domain=assessment_data.get('domain', ''),
                timestamp=datetime.now(),
                overall_score=overall_score,
                maturity_level=maturity_level,
                risk_summary=risk_summary,
                recommendations=recommendations,
                compliance_status=compliance_status,
                identity_analysis=identity_analysis,
                permission_analysis=permission_analysis,
                security_gaps=security_gaps,
                implementation_roadmap=implementation_roadmap
            )
            
            logger.info(f"Zero trust analysis completed. Score: {overall_score:.1f}, Maturity: {maturity_level}")
            return result
            
        except Exception as e:
            logger.error(f"Error during zero trust analysis: {str(e)}")
            raise
    
    def _analyze_identities(self, identity_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze identity-related data"""
        human_identities = identity_data.get('human_identities', [])
        service_accounts = identity_data.get('service_accounts', [])
        privileged_accounts = identity_data.get('privileged_accounts', [])
        
        # Calculate identity metrics
        total_identities = len(human_identities) + len(service_accounts)
        privileged_ratio = len(privileged_accounts) / max(total_identities, 1)
        
        # Analyze MFA coverage
        mfa_enabled = sum(1 for user in human_identities if user.get('mfa_enabled', False))
        mfa_coverage = mfa_enabled / max(len(human_identities), 1)
        
        # Analyze password policies
        weak_passwords = sum(1 for user in human_identities if user.get('password_strength', 'weak') == 'weak')
        password_score = 1 - (weak_passwords / max(len(human_identities), 1))
        
        # Calculate identity verification score
        identity_score = (mfa_coverage * 0.4 + password_score * 0.3 + (1 - privileged_ratio) * 0.3) * 100
        
        return {
            'total_identities': total_identities,
            'human_identities': len(human_identities),
            'service_accounts': len(service_accounts),
            'privileged_accounts': len(privileged_accounts),
            'privileged_ratio': privileged_ratio,
            'mfa_coverage': mfa_coverage,
            'password_score': password_score,
            'identity_verification_score': identity_score,
            'high_risk_identities': [user for user in human_identities + service_accounts 
                                   if user.get('risk_level') == 'high'],
            'recommendations': self._get_identity_recommendations(mfa_coverage, password_score, privileged_ratio)
        }
    
    def _analyze_permissions(self, permission_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze permission and access control data"""
        permissions = permission_data.get('permissions', [])
        groups = permission_data.get('groups', [])
        roles = permission_data.get('roles', [])
        
        # Calculate permission metrics
        excessive_permissions = sum(1 for perm in permissions if perm.get('risk_level') == 'high')
        total_permissions = len(permissions)
        excessive_ratio = excessive_permissions / max(total_permissions, 1)
        
        # Analyze group memberships
        large_groups = [group for group in groups if len(group.get('members', [])) > 50]
        admin_groups = [group for group in groups if 'admin' in group.get('name', '').lower()]
        
        # Calculate least privilege score
        least_privilege_score = (1 - excessive_ratio) * 100
        
        return {
            'total_permissions': total_permissions,
            'excessive_permissions': excessive_permissions,
            'excessive_ratio': excessive_ratio,
            'total_groups': len(groups),
            'large_groups': len(large_groups),
            'admin_groups': len(admin_groups),
            'least_privilege_score': least_privilege_score,
            'high_risk_permissions': [perm for perm in permissions if perm.get('risk_level') == 'high'],
            'recommendations': self._get_permission_recommendations(excessive_ratio, len(large_groups), len(admin_groups))
        }
    
    def _analyze_security_config(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security configuration data"""
        policies = security_data.get('policies', [])
        audit_settings = security_data.get('audit_settings', {})
        encryption_status = security_data.get('encryption', {})
        
        # Calculate security configuration score
        policy_compliance = sum(1 for policy in policies if policy.get('compliant', False))
        policy_score = policy_compliance / max(len(policies), 1)
        
        audit_enabled = audit_settings.get('enabled', False)
        audit_comprehensive = audit_settings.get('comprehensive', False)
        audit_score = (0.5 if audit_enabled else 0) + (0.5 if audit_comprehensive else 0)
        
        encryption_score = encryption_status.get('score', 0) / 100
        
        security_config_score = (policy_score * 0.4 + audit_score * 0.3 + encryption_score * 0.3) * 100
        
        return {
            'total_policies': len(policies),
            'compliant_policies': policy_compliance,
            'policy_compliance_ratio': policy_score,
            'audit_enabled': audit_enabled,
            'audit_comprehensive': audit_comprehensive,
            'encryption_score': encryption_score,
            'security_config_score': security_config_score,
            'non_compliant_policies': [policy for policy in policies if not policy.get('compliant', False)],
            'recommendations': self._get_security_recommendations(policy_score, audit_score, encryption_score)
        }
    
    def _analyze_infrastructure(self, infrastructure_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze infrastructure and network data"""
        network_segments = infrastructure_data.get('network_segments', [])
        devices = infrastructure_data.get('devices', [])
        applications = infrastructure_data.get('applications', [])
        
        # Calculate network segmentation score
        segmented_networks = sum(1 for segment in network_segments if segment.get('segmented', False))
        segmentation_score = segmented_networks / max(len(network_segments), 1)
        
        # Calculate device compliance score
        compliant_devices = sum(1 for device in devices if device.get('compliant', False))
        device_compliance_score = compliant_devices / max(len(devices), 1)
        
        # Calculate application security score
        secure_apps = sum(1 for app in applications if app.get('secure', False))
        app_security_score = secure_apps / max(len(applications), 1)
        
        infrastructure_score = (segmentation_score * 0.4 + device_compliance_score * 0.3 + app_security_score * 0.3) * 100
        
        return {
            'network_segments': len(network_segments),
            'segmented_networks': segmented_networks,
            'segmentation_score': segmentation_score,
            'total_devices': len(devices),
            'compliant_devices': compliant_devices,
            'device_compliance_score': device_compliance_score,
            'total_applications': len(applications),
            'secure_applications': secure_apps,
            'app_security_score': app_security_score,
            'infrastructure_score': infrastructure_score,
            'recommendations': self._get_infrastructure_recommendations(segmentation_score, device_compliance_score, app_security_score)
        }
    
    def _calculate_overall_score(self, analysis_results: Dict[str, Any]) -> float:
        """Calculate overall zero trust score"""
        identity_score = analysis_results['identity'].get('identity_verification_score', 0)
        permission_score = analysis_results['permissions'].get('least_privilege_score', 0)
        security_score = analysis_results['security'].get('security_config_score', 0)
        infrastructure_score = analysis_results['infrastructure'].get('infrastructure_score', 0)
        
        # Apply weights
        weighted_score = (
            identity_score * self.scoring_weights['identity_verification'] +
            permission_score * self.scoring_weights['device_compliance'] +
            security_score * self.scoring_weights['data_protection'] +
            infrastructure_score * self.scoring_weights['network_segmentation']
        ) / (self.scoring_weights['identity_verification'] + 
             self.scoring_weights['device_compliance'] + 
             self.scoring_weights['data_protection'] + 
             self.scoring_weights['network_segmentation'])
        
        return round(weighted_score, 1)
    
    def _determine_maturity_level(self, score: float) -> str:
        """Determine zero trust maturity level based on score"""
        for level, (min_score, max_score) in self.maturity_thresholds.items():
            if min_score <= score < max_score:
                return level
        return 'advanced'  # For scores >= 75
    
    def _identify_security_gaps(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify critical security gaps"""
        gaps = []
        
        identity_analysis = analysis_results['identity_analysis']
        permission_analysis = analysis_results['permission_analysis']
        security_analysis = analysis_results['security_analysis']
        infrastructure_analysis = analysis_results['infrastructure_analysis']
        
        # Identity gaps
        if identity_analysis['mfa_coverage'] < 0.8:
            gaps.append({
                'category': 'Identity Verification',
                'gap': 'Insufficient MFA Coverage',
                'severity': 'High',
                'current_state': f"{identity_analysis['mfa_coverage']:.1%} MFA coverage",
                'target_state': '100% MFA coverage for all users',
                'impact': 'High risk of credential-based attacks'
            })
        
        # Permission gaps
        if permission_analysis['excessive_ratio'] > 0.2:
            gaps.append({
                'category': 'Least Privilege Access',
                'gap': 'Excessive Permissions',
                'severity': 'High',
                'current_state': f"{permission_analysis['excessive_ratio']:.1%} excessive permissions",
                'target_state': 'Less than 5% excessive permissions',
                'impact': 'Increased attack surface and privilege escalation risk'
            })
        
        # Security configuration gaps
        if security_analysis['policy_compliance_ratio'] < 0.9:
            gaps.append({
                'category': 'Security Policies',
                'gap': 'Non-compliant Security Policies',
                'severity': 'Medium',
                'current_state': f"{security_analysis['policy_compliance_ratio']:.1%} policy compliance",
                'target_state': '100% policy compliance',
                'impact': 'Inconsistent security posture'
            })
        
        return gaps
    
    def _generate_implementation_roadmap(self, roadmap_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate zero trust implementation roadmap"""
        current_score = roadmap_data['current_score']
        maturity_level = roadmap_data['maturity_level']
        recommendations = roadmap_data['recommendations']
        
        # Define phases based on current maturity
        if maturity_level == 'traditional':
            phases = [
                {
                    'phase': 1,
                    'name': 'Foundation',
                    'duration': '3-6 months',
                    'focus': 'Identity and Access Management',
                    'key_activities': [
                        'Implement MFA for all users',
                        'Establish privileged access management',
                        'Deploy identity governance',
                        'Baseline security policies'
                    ]
                },
                {
                    'phase': 2,
                    'name': 'Expansion',
                    'duration': '6-12 months',
                    'focus': 'Device and Network Security',
                    'key_activities': [
                        'Implement device compliance',
                        'Deploy network segmentation',
                        'Enhance monitoring and analytics',
                        'Application security controls'
                    ]
                },
                {
                    'phase': 3,
                    'name': 'Optimization',
                    'duration': '12-18 months',
                    'focus': 'Advanced Zero Trust',
                    'key_activities': [
                        'Advanced threat protection',
                        'Behavioral analytics',
                        'Automated response',
                        'Continuous compliance'
                    ]
                }
            ]
        elif maturity_level == 'initial':
            phases = [
                {
                    'phase': 1,
                    'name': 'Enhancement',
                    'duration': '3-6 months',
                    'focus': 'Strengthen Current Controls',
                    'key_activities': [
                        'Improve MFA coverage',
                        'Reduce excessive permissions',
                        'Enhance monitoring',
                        'Policy compliance'
                    ]
                },
                {
                    'phase': 2,
                    'name': 'Advanced Implementation',
                    'duration': '6-12 months',
                    'focus': 'Advanced Zero Trust Features',
                    'key_activities': [
                        'Behavioral analytics',
                        'Advanced threat protection',
                        'Automated remediation',
                        'Continuous assessment'
                    ]
                }
            ]
        else:
            phases = [
                {
                    'phase': 1,
                    'name': 'Optimization',
                    'duration': '3-6 months',
                    'focus': 'Fine-tuning and Automation',
                    'key_activities': [
                        'Optimize existing controls',
                        'Implement automation',
                        'Advanced analytics',
                        'Continuous improvement'
                    ]
                }
            ]
        
        return {
            'current_maturity': maturity_level,
            'target_maturity': 'advanced',
            'estimated_timeline': f"{sum(len(phase['duration'].split('-')[0]) for phase in phases)}-{sum(len(phase['duration'].split('-')[1].split()[0]) for phase in phases)} months",
            'phases': phases,
            'success_metrics': [
                'Zero Trust Score > 85%',
                'MFA Coverage > 95%',
                'Excessive Permissions < 5%',
                'Policy Compliance > 95%',
                'Mean Time to Detection < 1 hour'
            ]
        }
    
    def _get_identity_recommendations(self, mfa_coverage: float, password_score: float, privileged_ratio: float) -> List[str]:
        """Get identity-specific recommendations"""
        recommendations = []
        
        if mfa_coverage < 0.9:
            recommendations.append("Implement MFA for all user accounts")
        if password_score < 0.8:
            recommendations.append("Enforce strong password policies")
        if privileged_ratio > 0.1:
            recommendations.append("Reduce number of privileged accounts")
        
        return recommendations
    
    def _get_permission_recommendations(self, excessive_ratio: float, large_groups: int, admin_groups: int) -> List[str]:
        """Get permission-specific recommendations"""
        recommendations = []
        
        if excessive_ratio > 0.1:
            recommendations.append("Review and remove excessive permissions")
        if large_groups > 5:
            recommendations.append("Break down large security groups")
        if admin_groups > 3:
            recommendations.append("Consolidate administrative groups")
        
        return recommendations
    
    def _get_security_recommendations(self, policy_score: float, audit_score: float, encryption_score: float) -> List[str]:
        """Get security configuration recommendations"""
        recommendations = []
        
        if policy_score < 0.9:
            recommendations.append("Update non-compliant security policies")
        if audit_score < 0.8:
            recommendations.append("Enable comprehensive audit logging")
        if encryption_score < 0.8:
            recommendations.append("Implement data encryption at rest and in transit")
        
        return recommendations
    
    def _get_infrastructure_recommendations(self, segmentation_score: float, device_score: float, app_score: float) -> List[str]:
        """Get infrastructure-specific recommendations"""
        recommendations = []
        
        if segmentation_score < 0.8:
            recommendations.append("Implement network micro-segmentation")
        if device_score < 0.8:
            recommendations.append("Enforce device compliance policies")
        if app_score < 0.8:
            recommendations.append("Secure applications with zero trust controls")
        
        return recommendations
    
    def export_results(self, result: ZeroTrustAssessmentResult, format: str = 'json') -> str:
        """Export analysis results in specified format"""
        if format.lower() == 'json':
            return json.dumps(asdict(result), indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")

