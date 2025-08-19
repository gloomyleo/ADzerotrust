"""
Compliance Checker - Evaluates compliance against security frameworks for ADZero Trust
Assesses compliance with NIST, ISO 27001, CIS Controls, and other frameworks

Author: Moazzam Jafri
"""

import logging
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ComplianceStatus(Enum):
    COMPLIANT = "Compliant"
    PARTIALLY_COMPLIANT = "Partially Compliant"
    NON_COMPLIANT = "Non-Compliant"
    NOT_ASSESSED = "Not Assessed"

class Framework(Enum):
    NIST_CSF = "NIST Cybersecurity Framework"
    NIST_800_53 = "NIST SP 800-53"
    ISO_27001 = "ISO 27001"
    CIS_CONTROLS = "CIS Controls"
    SOX = "Sarbanes-Oxley Act"
    PCI_DSS = "PCI Data Security Standard"
    GDPR = "General Data Protection Regulation"
    HIPAA = "Health Insurance Portability and Accountability Act"

@dataclass
class ComplianceControl:
    """Individual compliance control assessment"""
    control_id: str
    framework: Framework
    title: str
    description: str
    status: ComplianceStatus
    compliance_score: float
    evidence: List[str]
    gaps: List[str]
    recommendations: List[str]
    risk_level: str

@dataclass
class FrameworkAssessment:
    """Complete framework compliance assessment"""
    framework: Framework
    overall_status: ComplianceStatus
    compliance_percentage: float
    total_controls: int
    compliant_controls: int
    partially_compliant_controls: int
    non_compliant_controls: int
    control_assessments: List[ComplianceControl]
    key_gaps: List[str]
    priority_actions: List[str]

class ComplianceChecker:
    """Evaluates compliance against multiple security frameworks"""
    
    def __init__(self):
        self.supported_frameworks = [
            Framework.NIST_CSF,
            Framework.NIST_800_53,
            Framework.ISO_27001,
            Framework.CIS_CONTROLS,
            Framework.SOX,
            Framework.PCI_DSS,
            Framework.GDPR
        ]
        
        self.control_mappings = self._define_control_mappings()
    
    def check_compliance(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check compliance against multiple frameworks
        
        Args:
            analysis_data: Complete analysis results
            
        Returns:
            Dict containing comprehensive compliance assessment
        """
        logger.info("Checking compliance against security frameworks")
        
        try:
            framework_assessments = []
            
            # Assess each supported framework
            for framework in self.supported_frameworks:
                assessment = self._assess_framework_compliance(framework, analysis_data)
                framework_assessments.append(assessment)
            
            # Calculate overall compliance metrics
            overall_metrics = self._calculate_overall_metrics(framework_assessments)
            
            # Identify common gaps across frameworks
            common_gaps = self._identify_common_gaps(framework_assessments)
            
            # Generate compliance roadmap
            compliance_roadmap = self._generate_compliance_roadmap(framework_assessments)
            
            return {
                'overall_compliance_score': overall_metrics['overall_score'],
                'framework_assessments': [self._framework_to_dict(f) for f in framework_assessments],
                'compliance_summary': overall_metrics,
                'common_gaps': common_gaps,
                'compliance_roadmap': compliance_roadmap,
                'regulatory_requirements': self._get_regulatory_requirements(),
                'audit_readiness': self._assess_audit_readiness(framework_assessments)
            }
            
        except Exception as e:
            logger.error(f"Error checking compliance: {str(e)}")
            raise
    
    def _assess_framework_compliance(self, framework: Framework, analysis_data: Dict[str, Any]) -> FrameworkAssessment:
        """Assess compliance for a specific framework"""
        
        if framework == Framework.NIST_CSF:
            return self._assess_nist_csf_compliance(analysis_data)
        elif framework == Framework.ISO_27001:
            return self._assess_iso27001_compliance(analysis_data)
        elif framework == Framework.CIS_CONTROLS:
            return self._assess_cis_controls_compliance(analysis_data)
        elif framework == Framework.SOX:
            return self._assess_sox_compliance(analysis_data)
        elif framework == Framework.PCI_DSS:
            return self._assess_pci_dss_compliance(analysis_data)
        elif framework == Framework.GDPR:
            return self._assess_gdpr_compliance(analysis_data)
        else:
            # Default assessment for unsupported frameworks
            return FrameworkAssessment(
                framework=framework,
                overall_status=ComplianceStatus.NOT_ASSESSED,
                compliance_percentage=0.0,
                total_controls=0,
                compliant_controls=0,
                partially_compliant_controls=0,
                non_compliant_controls=0,
                control_assessments=[],
                key_gaps=["Framework assessment not implemented"],
                priority_actions=["Implement framework-specific assessment"]
            )
    
    def _assess_nist_csf_compliance(self, analysis_data: Dict[str, Any]) -> FrameworkAssessment:
        """Assess NIST Cybersecurity Framework compliance"""
        controls = []
        
        identity_analysis = analysis_data.get('identity_analysis', {})
        security_analysis = analysis_data.get('security_analysis', {})
        
        # PR.AC-1: Identities and credentials are issued, managed, verified, revoked, and audited
        mfa_coverage = identity_analysis.get('mfa_coverage', 0)
        if mfa_coverage >= 0.9:
            status = ComplianceStatus.COMPLIANT
            score = 100.0
            evidence = [f"MFA coverage: {mfa_coverage:.1%}"]
            gaps = []
        elif mfa_coverage >= 0.5:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            score = 60.0
            evidence = [f"Partial MFA coverage: {mfa_coverage:.1%}"]
            gaps = ["Incomplete MFA deployment"]
        else:
            status = ComplianceStatus.NON_COMPLIANT
            score = 20.0
            evidence = [f"Low MFA coverage: {mfa_coverage:.1%}"]
            gaps = ["MFA not implemented for most users"]
        
        controls.append(ComplianceControl(
            control_id="PR.AC-1",
            framework=Framework.NIST_CSF,
            title="Identity Management",
            description="Identities and credentials are issued, managed, verified, revoked, and audited",
            status=status,
            compliance_score=score,
            evidence=evidence,
            gaps=gaps,
            recommendations=["Implement comprehensive identity management"] if gaps else [],
            risk_level="High" if status == ComplianceStatus.NON_COMPLIANT else "Medium"
        ))
        
        # DE.AE-3: Event data are collected and correlated from multiple sources and sensors
        audit_enabled = security_analysis.get('audit_enabled', False)
        audit_comprehensive = security_analysis.get('audit_comprehensive', False)
        
        if audit_enabled and audit_comprehensive:
            status = ComplianceStatus.COMPLIANT
            score = 100.0
            evidence = ["Comprehensive audit logging enabled"]
            gaps = []
        elif audit_enabled:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            score = 70.0
            evidence = ["Basic audit logging enabled"]
            gaps = ["Limited audit coverage"]
        else:
            status = ComplianceStatus.NON_COMPLIANT
            score = 10.0
            evidence = ["Audit logging not enabled"]
            gaps = ["No security event logging"]
        
        controls.append(ComplianceControl(
            control_id="DE.AE-3",
            framework=Framework.NIST_CSF,
            title="Event Logging",
            description="Event data are collected and correlated from multiple sources and sensors",
            status=status,
            compliance_score=score,
            evidence=evidence,
            gaps=gaps,
            recommendations=["Enable comprehensive audit logging"] if gaps else [],
            risk_level="High" if status == ComplianceStatus.NON_COMPLIANT else "Low"
        ))
        
        # Calculate framework compliance
        total_controls = len(controls)
        compliant = len([c for c in controls if c.status == ComplianceStatus.COMPLIANT])
        partially_compliant = len([c for c in controls if c.status == ComplianceStatus.PARTIALLY_COMPLIANT])
        non_compliant = len([c for c in controls if c.status == ComplianceStatus.NON_COMPLIANT])
        
        compliance_percentage = sum(c.compliance_score for c in controls) / max(total_controls * 100, 1)
        
        if compliance_percentage >= 90:
            overall_status = ComplianceStatus.COMPLIANT
        elif compliance_percentage >= 60:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            overall_status = ComplianceStatus.NON_COMPLIANT
        
        return FrameworkAssessment(
            framework=Framework.NIST_CSF,
            overall_status=overall_status,
            compliance_percentage=compliance_percentage,
            total_controls=total_controls,
            compliant_controls=compliant,
            partially_compliant_controls=partially_compliant,
            non_compliant_controls=non_compliant,
            control_assessments=controls,
            key_gaps=[gap for control in controls for gap in control.gaps],
            priority_actions=[rec for control in controls for rec in control.recommendations]
        )
    
    def _assess_iso27001_compliance(self, analysis_data: Dict[str, Any]) -> FrameworkAssessment:
        """Assess ISO 27001 compliance"""
        controls = []
        
        identity_analysis = analysis_data.get('identity_analysis', {})
        permission_analysis = analysis_data.get('permission_analysis', {})
        
        # A.9.2.1 User registration and de-registration
        total_identities = identity_analysis.get('total_identities', 0)
        if total_identities > 0:
            status = ComplianceStatus.COMPLIANT
            score = 100.0
            evidence = [f"Identity management for {total_identities} accounts"]
            gaps = []
        else:
            status = ComplianceStatus.NON_COMPLIANT
            score = 0.0
            evidence = ["No identity management system"]
            gaps = ["Identity management not implemented"]
        
        controls.append(ComplianceControl(
            control_id="A.9.2.1",
            framework=Framework.ISO_27001,
            title="User Registration",
            description="User registration and de-registration process",
            status=status,
            compliance_score=score,
            evidence=evidence,
            gaps=gaps,
            recommendations=["Implement formal user registration process"] if gaps else [],
            risk_level="Medium"
        ))
        
        # A.9.2.3 Management of privileged access rights
        privileged_ratio = identity_analysis.get('privileged_ratio', 1)
        if privileged_ratio <= 0.1:
            status = ComplianceStatus.COMPLIANT
            score = 100.0
            evidence = [f"Privileged accounts: {privileged_ratio:.1%}"]
            gaps = []
        elif privileged_ratio <= 0.2:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            score = 70.0
            evidence = [f"Some privileged accounts: {privileged_ratio:.1%}"]
            gaps = ["Too many privileged accounts"]
        else:
            status = ComplianceStatus.NON_COMPLIANT
            score = 30.0
            evidence = [f"Many privileged accounts: {privileged_ratio:.1%}"]
            gaps = ["Excessive privileged accounts"]
        
        controls.append(ComplianceControl(
            control_id="A.9.2.3",
            framework=Framework.ISO_27001,
            title="Privileged Access Management",
            description="Management of privileged access rights",
            status=status,
            compliance_score=score,
            evidence=evidence,
            gaps=gaps,
            recommendations=["Implement privileged access management"] if gaps else [],
            risk_level="High" if status == ComplianceStatus.NON_COMPLIANT else "Medium"
        ))
        
        # Calculate framework compliance
        total_controls = len(controls)
        compliant = len([c for c in controls if c.status == ComplianceStatus.COMPLIANT])
        partially_compliant = len([c for c in controls if c.status == ComplianceStatus.PARTIALLY_COMPLIANT])
        non_compliant = len([c for c in controls if c.status == ComplianceStatus.NON_COMPLIANT])
        
        compliance_percentage = sum(c.compliance_score for c in controls) / max(total_controls * 100, 1)
        
        if compliance_percentage >= 90:
            overall_status = ComplianceStatus.COMPLIANT
        elif compliance_percentage >= 60:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            overall_status = ComplianceStatus.NON_COMPLIANT
        
        return FrameworkAssessment(
            framework=Framework.ISO_27001,
            overall_status=overall_status,
            compliance_percentage=compliance_percentage,
            total_controls=total_controls,
            compliant_controls=compliant,
            partially_compliant_controls=partially_compliant,
            non_compliant_controls=non_compliant,
            control_assessments=controls,
            key_gaps=[gap for control in controls for gap in control.gaps],
            priority_actions=[rec for control in controls for rec in control.recommendations]
        )
    
    def _assess_cis_controls_compliance(self, analysis_data: Dict[str, Any]) -> FrameworkAssessment:
        """Assess CIS Controls compliance"""
        # Simplified assessment for demonstration
        return FrameworkAssessment(
            framework=Framework.CIS_CONTROLS,
            overall_status=ComplianceStatus.PARTIALLY_COMPLIANT,
            compliance_percentage=65.0,
            total_controls=18,
            compliant_controls=8,
            partially_compliant_controls=6,
            non_compliant_controls=4,
            control_assessments=[],
            key_gaps=["Asset inventory incomplete", "Vulnerability management gaps"],
            priority_actions=["Complete asset inventory", "Implement vulnerability scanning"]
        )
    
    def _assess_sox_compliance(self, analysis_data: Dict[str, Any]) -> FrameworkAssessment:
        """Assess SOX compliance"""
        # Simplified assessment for demonstration
        return FrameworkAssessment(
            framework=Framework.SOX,
            overall_status=ComplianceStatus.PARTIALLY_COMPLIANT,
            compliance_percentage=70.0,
            total_controls=5,
            compliant_controls=2,
            partially_compliant_controls=2,
            non_compliant_controls=1,
            control_assessments=[],
            key_gaps=["Access controls need improvement", "Change management gaps"],
            priority_actions=["Strengthen access controls", "Implement change management"]
        )
    
    def _assess_pci_dss_compliance(self, analysis_data: Dict[str, Any]) -> FrameworkAssessment:
        """Assess PCI DSS compliance"""
        # Simplified assessment for demonstration
        return FrameworkAssessment(
            framework=Framework.PCI_DSS,
            overall_status=ComplianceStatus.NON_COMPLIANT,
            compliance_percentage=40.0,
            total_controls=12,
            compliant_controls=3,
            partially_compliant_controls=4,
            non_compliant_controls=5,
            control_assessments=[],
            key_gaps=["Network segmentation insufficient", "Encryption gaps"],
            priority_actions=["Implement network segmentation", "Deploy encryption"]
        )
    
    def _assess_gdpr_compliance(self, analysis_data: Dict[str, Any]) -> FrameworkAssessment:
        """Assess GDPR compliance"""
        # Simplified assessment for demonstration
        return FrameworkAssessment(
            framework=Framework.GDPR,
            overall_status=ComplianceStatus.PARTIALLY_COMPLIANT,
            compliance_percentage=60.0,
            total_controls=8,
            compliant_controls=3,
            partially_compliant_controls=3,
            non_compliant_controls=2,
            control_assessments=[],
            key_gaps=["Data protection impact assessments needed", "Privacy by design gaps"],
            priority_actions=["Conduct DPIAs", "Implement privacy by design"]
        )
    
    def _calculate_overall_metrics(self, assessments: List[FrameworkAssessment]) -> Dict[str, Any]:
        """Calculate overall compliance metrics"""
        total_score = sum(a.compliance_percentage for a in assessments)
        average_score = total_score / max(len(assessments), 1)
        
        status_counts = {
            ComplianceStatus.COMPLIANT.value: 0,
            ComplianceStatus.PARTIALLY_COMPLIANT.value: 0,
            ComplianceStatus.NON_COMPLIANT.value: 0,
            ComplianceStatus.NOT_ASSESSED.value: 0
        }
        
        for assessment in assessments:
            status_counts[assessment.overall_status.value] += 1
        
        return {
            'overall_score': round(average_score, 1),
            'total_frameworks': len(assessments),
            'framework_status_distribution': status_counts,
            'compliant_frameworks': status_counts[ComplianceStatus.COMPLIANT.value],
            'partially_compliant_frameworks': status_counts[ComplianceStatus.PARTIALLY_COMPLIANT.value],
            'non_compliant_frameworks': status_counts[ComplianceStatus.NON_COMPLIANT.value]
        }
    
    def _identify_common_gaps(self, assessments: List[FrameworkAssessment]) -> List[Dict[str, Any]]:
        """Identify gaps common across multiple frameworks"""
        gap_counts = {}
        
        for assessment in assessments:
            for gap in assessment.key_gaps:
                if gap not in gap_counts:
                    gap_counts[gap] = {'count': 0, 'frameworks': []}
                gap_counts[gap]['count'] += 1
                gap_counts[gap]['frameworks'].append(assessment.framework.value)
        
        # Return gaps that appear in multiple frameworks
        common_gaps = []
        for gap, data in gap_counts.items():
            if data['count'] > 1:
                common_gaps.append({
                    'gap': gap,
                    'affected_frameworks': data['frameworks'],
                    'frequency': data['count']
                })
        
        return sorted(common_gaps, key=lambda x: x['frequency'], reverse=True)
    
    def _generate_compliance_roadmap(self, assessments: List[FrameworkAssessment]) -> Dict[str, Any]:
        """Generate compliance improvement roadmap"""
        # Identify priority frameworks (those with lowest compliance)
        priority_frameworks = sorted(assessments, key=lambda x: x.compliance_percentage)[:3]
        
        roadmap_phases = []
        
        # Phase 1: Address critical gaps
        critical_actions = []
        for framework in priority_frameworks:
            critical_actions.extend(framework.priority_actions[:2])
        
        roadmap_phases.append({
            'phase': 1,
            'name': 'Critical Compliance Gaps',
            'duration': '1-3 months',
            'focus': 'Address highest priority compliance gaps',
            'actions': list(set(critical_actions))[:5],
            'target_frameworks': [f.framework.value for f in priority_frameworks]
        })
        
        # Phase 2: Comprehensive compliance
        roadmap_phases.append({
            'phase': 2,
            'name': 'Comprehensive Compliance',
            'duration': '3-6 months',
            'focus': 'Achieve full compliance across all frameworks',
            'actions': [
                'Complete remaining control implementations',
                'Conduct compliance assessments',
                'Prepare for external audits',
                'Establish ongoing compliance monitoring'
            ],
            'target_frameworks': [a.framework.value for a in assessments]
        })
        
        return {
            'phases': roadmap_phases,
            'total_duration': '6 months',
            'success_criteria': [
                'All frameworks achieve >90% compliance',
                'Critical gaps addressed',
                'Audit readiness achieved'
            ]
        }
    
    def _get_regulatory_requirements(self) -> Dict[str, Any]:
        """Get regulatory requirements summary"""
        return {
            'applicable_regulations': [
                'GDPR - General Data Protection Regulation',
                'SOX - Sarbanes-Oxley Act',
                'HIPAA - Health Insurance Portability and Accountability Act',
                'PCI DSS - Payment Card Industry Data Security Standard'
            ],
            'key_requirements': [
                'Data protection and privacy controls',
                'Access controls and authentication',
                'Audit logging and monitoring',
                'Incident response procedures',
                'Regular security assessments'
            ],
            'compliance_deadlines': {
                'GDPR': 'Ongoing compliance required',
                'SOX': 'Annual compliance certification',
                'PCI DSS': 'Annual assessment required'
            }
        }
    
    def _assess_audit_readiness(self, assessments: List[FrameworkAssessment]) -> Dict[str, Any]:
        """Assess readiness for external audits"""
        average_compliance = sum(a.compliance_percentage for a in assessments) / max(len(assessments), 1)
        
        if average_compliance >= 90:
            readiness_level = "High"
            readiness_description = "Organization is well-prepared for external audits"
        elif average_compliance >= 70:
            readiness_level = "Medium"
            readiness_description = "Some preparation needed before external audits"
        else:
            readiness_level = "Low"
            readiness_description = "Significant preparation required before external audits"
        
        return {
            'readiness_level': readiness_level,
            'readiness_score': average_compliance,
            'description': readiness_description,
            'preparation_needed': [
                'Address critical compliance gaps',
                'Prepare compliance documentation',
                'Conduct internal assessments',
                'Train audit response team'
            ] if readiness_level != "High" else ['Maintain current compliance posture'],
            'estimated_preparation_time': '1-2 months' if readiness_level == "Medium" else '3-6 months' if readiness_level == "Low" else 'Audit ready'
        }
    
    def _framework_to_dict(self, framework: FrameworkAssessment) -> Dict[str, Any]:
        """Convert FrameworkAssessment to dictionary"""
        return {
            'framework': framework.framework.value,
            'overall_status': framework.overall_status.value,
            'compliance_percentage': framework.compliance_percentage,
            'total_controls': framework.total_controls,
            'compliant_controls': framework.compliant_controls,
            'partially_compliant_controls': framework.partially_compliant_controls,
            'non_compliant_controls': framework.non_compliant_controls,
            'key_gaps': framework.key_gaps,
            'priority_actions': framework.priority_actions,
            'control_assessments': [self._control_to_dict(c) for c in framework.control_assessments]
        }
    
    def _control_to_dict(self, control: ComplianceControl) -> Dict[str, Any]:
        """Convert ComplianceControl to dictionary"""
        return {
            'control_id': control.control_id,
            'framework': control.framework.value,
            'title': control.title,
            'description': control.description,
            'status': control.status.value,
            'compliance_score': control.compliance_score,
            'evidence': control.evidence,
            'gaps': control.gaps,
            'recommendations': control.recommendations,
            'risk_level': control.risk_level
        }
    
    def _define_control_mappings(self) -> Dict[str, Any]:
        """Define control mappings between frameworks (placeholder for future enhancement)"""
        return {}

