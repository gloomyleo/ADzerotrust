"""
Maturity Assessor - Evaluates Zero Trust maturity level for ADZero Trust
Assesses current state against Zero Trust maturity models

Author: Moazzam Jafri
"""

import logging
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class MaturityLevel(Enum):
    TRADITIONAL = "Traditional"
    INITIAL = "Initial" 
    INTERMEDIATE = "Intermediate"
    ADVANCED = "Advanced"

@dataclass
class MaturityDimension:
    """Individual maturity dimension assessment"""
    name: str
    current_level: MaturityLevel
    score: float
    description: str
    strengths: List[str]
    gaps: List[str]
    next_steps: List[str]

class MaturityAssessor:
    """Evaluates Zero Trust maturity across multiple dimensions"""
    
    def __init__(self):
        self.maturity_dimensions = [
            "Identity Verification",
            "Device Security", 
            "Network Security",
            "Application Workloads",
            "Data",
            "Infrastructure",
            "Visibility & Analytics"
        ]
        
        self.maturity_criteria = self._define_maturity_criteria()
    
    def assess_maturity(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess Zero Trust maturity across all dimensions
        
        Args:
            analysis_data: Complete analysis results
            
        Returns:
            Dict containing comprehensive maturity assessment
        """
        logger.info("Assessing Zero Trust maturity")
        
        try:
            dimension_assessments = []
            
            # Assess each dimension
            for dimension in self.maturity_dimensions:
                assessment = self._assess_dimension(dimension, analysis_data)
                dimension_assessments.append(assessment)
            
            # Calculate overall maturity
            overall_score = sum(d.score for d in dimension_assessments) / len(dimension_assessments)
            overall_level = self._determine_maturity_level(overall_score)
            
            # Generate maturity roadmap
            roadmap = self._generate_maturity_roadmap(dimension_assessments, overall_level)
            
            return {
                'overall_maturity_level': overall_level.value,
                'overall_score': round(overall_score, 1),
                'dimension_assessments': [self._dimension_to_dict(d) for d in dimension_assessments],
                'maturity_distribution': self._calculate_maturity_distribution(dimension_assessments),
                'maturity_roadmap': roadmap,
                'benchmark_comparison': self._generate_benchmark_comparison(overall_score),
                'improvement_priorities': self._identify_improvement_priorities(dimension_assessments)
            }
            
        except Exception as e:
            logger.error(f"Error assessing maturity: {str(e)}")
            raise
    
    def _assess_dimension(self, dimension: str, analysis_data: Dict[str, Any]) -> MaturityDimension:
        """Assess maturity for a specific dimension"""
        
        if dimension == "Identity Verification":
            return self._assess_identity_verification(analysis_data)
        elif dimension == "Device Security":
            return self._assess_device_security(analysis_data)
        elif dimension == "Network Security":
            return self._assess_network_security(analysis_data)
        elif dimension == "Application Workloads":
            return self._assess_application_workloads(analysis_data)
        elif dimension == "Data":
            return self._assess_data_protection(analysis_data)
        elif dimension == "Infrastructure":
            return self._assess_infrastructure(analysis_data)
        elif dimension == "Visibility & Analytics":
            return self._assess_visibility_analytics(analysis_data)
        else:
            # Default assessment
            return MaturityDimension(
                name=dimension,
                current_level=MaturityLevel.INITIAL,
                score=30.0,
                description="Assessment not implemented",
                strengths=[],
                gaps=["Assessment methodology not defined"],
                next_steps=["Define assessment criteria"]
            )
    
    def _assess_identity_verification(self, analysis_data: Dict[str, Any]) -> MaturityDimension:
        """Assess identity verification maturity"""
        identity_analysis = analysis_data.get('identity_analysis', {})
        
        mfa_coverage = identity_analysis.get('mfa_coverage', 0)
        password_score = identity_analysis.get('password_score', 0)
        privileged_ratio = identity_analysis.get('privileged_ratio', 1)
        
        # Calculate dimension score
        score = (
            (mfa_coverage * 40) +
            (password_score * 30) +
            ((1 - min(privileged_ratio, 0.2) / 0.2) * 30)
        )
        
        level = self._determine_maturity_level(score)
        
        strengths = []
        gaps = []
        next_steps = []
        
        if mfa_coverage > 0.8:
            strengths.append("High MFA coverage implemented")
        else:
            gaps.append("Insufficient MFA coverage")
            next_steps.append("Expand MFA to all users")
        
        if password_score > 0.8:
            strengths.append("Strong password policies enforced")
        else:
            gaps.append("Weak password policies")
            next_steps.append("Implement strong password requirements")
        
        if privileged_ratio < 0.1:
            strengths.append("Limited privileged accounts")
        else:
            gaps.append("Too many privileged accounts")
            next_steps.append("Implement privileged access management")
        
        return MaturityDimension(
            name="Identity Verification",
            current_level=level,
            score=score,
            description=f"Identity verification maturity based on MFA coverage ({mfa_coverage:.1%}), password policies, and privileged access management",
            strengths=strengths,
            gaps=gaps,
            next_steps=next_steps
        )
    
    def _assess_device_security(self, analysis_data: Dict[str, Any]) -> MaturityDimension:
        """Assess device security maturity"""
        infrastructure_analysis = analysis_data.get('infrastructure_analysis', {})
        
        device_compliance = infrastructure_analysis.get('device_compliance_score', 0)
        total_devices = infrastructure_analysis.get('total_devices', 0)
        
        # Calculate score based on device compliance
        score = device_compliance * 100
        level = self._determine_maturity_level(score)
        
        strengths = []
        gaps = []
        next_steps = []
        
        if device_compliance > 0.8:
            strengths.append("High device compliance rate")
        else:
            gaps.append("Low device compliance")
            next_steps.append("Implement device compliance policies")
        
        if total_devices > 0:
            strengths.append("Device inventory established")
        else:
            gaps.append("No device inventory")
            next_steps.append("Establish device inventory and monitoring")
        
        return MaturityDimension(
            name="Device Security",
            current_level=level,
            score=score,
            description=f"Device security maturity based on compliance rate ({device_compliance:.1%}) and device management",
            strengths=strengths,
            gaps=gaps,
            next_steps=next_steps
        )
    
    def _assess_network_security(self, analysis_data: Dict[str, Any]) -> MaturityDimension:
        """Assess network security maturity"""
        infrastructure_analysis = analysis_data.get('infrastructure_analysis', {})
        
        segmentation_score = infrastructure_analysis.get('segmentation_score', 0)
        network_segments = infrastructure_analysis.get('network_segments', 0)
        
        # Calculate score based on network segmentation
        score = segmentation_score * 100
        level = self._determine_maturity_level(score)
        
        strengths = []
        gaps = []
        next_steps = []
        
        if segmentation_score > 0.8:
            strengths.append("Effective network segmentation implemented")
        else:
            gaps.append("Insufficient network segmentation")
            next_steps.append("Implement micro-segmentation")
        
        if network_segments > 5:
            strengths.append("Multiple network segments defined")
        else:
            gaps.append("Limited network segmentation")
            next_steps.append("Design comprehensive segmentation strategy")
        
        return MaturityDimension(
            name="Network Security",
            current_level=level,
            score=score,
            description=f"Network security maturity based on segmentation ({segmentation_score:.1%}) and network architecture",
            strengths=strengths,
            gaps=gaps,
            next_steps=next_steps
        )
    
    def _assess_application_workloads(self, analysis_data: Dict[str, Any]) -> MaturityDimension:
        """Assess application workload security maturity"""
        infrastructure_analysis = analysis_data.get('infrastructure_analysis', {})
        
        app_security_score = infrastructure_analysis.get('app_security_score', 0)
        total_apps = infrastructure_analysis.get('total_applications', 0)
        
        # Calculate score based on application security
        score = app_security_score * 100
        level = self._determine_maturity_level(score)
        
        strengths = []
        gaps = []
        next_steps = []
        
        if app_security_score > 0.8:
            strengths.append("High application security posture")
        else:
            gaps.append("Inadequate application security")
            next_steps.append("Implement application security controls")
        
        if total_apps > 0:
            strengths.append("Application inventory maintained")
        else:
            gaps.append("No application inventory")
            next_steps.append("Establish application inventory and assessment")
        
        return MaturityDimension(
            name="Application Workloads",
            current_level=level,
            score=score,
            description=f"Application security maturity based on security controls ({app_security_score:.1%}) and application management",
            strengths=strengths,
            gaps=gaps,
            next_steps=next_steps
        )
    
    def _assess_data_protection(self, analysis_data: Dict[str, Any]) -> MaturityDimension:
        """Assess data protection maturity"""
        security_analysis = analysis_data.get('security_analysis', {})
        
        encryption_score = security_analysis.get('encryption_score', 0)
        
        # Calculate score based on data protection measures
        score = encryption_score * 100
        level = self._determine_maturity_level(score)
        
        strengths = []
        gaps = []
        next_steps = []
        
        if encryption_score > 0.8:
            strengths.append("Strong data encryption implemented")
        else:
            gaps.append("Insufficient data encryption")
            next_steps.append("Implement comprehensive data encryption")
        
        return MaturityDimension(
            name="Data",
            current_level=level,
            score=score,
            description=f"Data protection maturity based on encryption ({encryption_score:.1%}) and data governance",
            strengths=strengths,
            gaps=gaps,
            next_steps=next_steps
        )
    
    def _assess_infrastructure(self, analysis_data: Dict[str, Any]) -> MaturityDimension:
        """Assess infrastructure security maturity"""
        infrastructure_analysis = analysis_data.get('infrastructure_analysis', {})
        
        infrastructure_score = infrastructure_analysis.get('infrastructure_score', 0)
        
        level = self._determine_maturity_level(infrastructure_score)
        
        return MaturityDimension(
            name="Infrastructure",
            current_level=level,
            score=infrastructure_score,
            description=f"Infrastructure security maturity based on overall infrastructure assessment",
            strengths=["Infrastructure assessment completed"],
            gaps=["Detailed infrastructure analysis needed"],
            next_steps=["Implement infrastructure security controls"]
        )
    
    def _assess_visibility_analytics(self, analysis_data: Dict[str, Any]) -> MaturityDimension:
        """Assess visibility and analytics maturity"""
        security_analysis = analysis_data.get('security_analysis', {})
        
        audit_enabled = security_analysis.get('audit_enabled', False)
        audit_comprehensive = security_analysis.get('audit_comprehensive', False)
        
        # Calculate score based on monitoring and analytics capabilities
        score = 0
        if audit_enabled:
            score += 50
        if audit_comprehensive:
            score += 50
        
        level = self._determine_maturity_level(score)
        
        strengths = []
        gaps = []
        next_steps = []
        
        if audit_enabled:
            strengths.append("Basic audit logging enabled")
        else:
            gaps.append("Audit logging not enabled")
            next_steps.append("Enable comprehensive audit logging")
        
        if audit_comprehensive:
            strengths.append("Comprehensive audit coverage")
        else:
            gaps.append("Limited audit coverage")
            next_steps.append("Expand audit logging coverage")
        
        return MaturityDimension(
            name="Visibility & Analytics",
            current_level=level,
            score=score,
            description=f"Visibility and analytics maturity based on audit logging and monitoring capabilities",
            strengths=strengths,
            gaps=gaps,
            next_steps=next_steps
        )
    
    def _determine_maturity_level(self, score: float) -> MaturityLevel:
        """Determine maturity level based on score"""
        if score >= 75:
            return MaturityLevel.ADVANCED
        elif score >= 50:
            return MaturityLevel.INTERMEDIATE
        elif score >= 30:
            return MaturityLevel.INITIAL
        else:
            return MaturityLevel.TRADITIONAL
    
    def _calculate_maturity_distribution(self, assessments: List[MaturityDimension]) -> Dict[str, int]:
        """Calculate distribution of maturity levels across dimensions"""
        distribution = {level.value: 0 for level in MaturityLevel}
        
        for assessment in assessments:
            distribution[assessment.current_level.value] += 1
        
        return distribution
    
    def _generate_maturity_roadmap(self, assessments: List[MaturityDimension], overall_level: MaturityLevel) -> Dict[str, Any]:
        """Generate maturity improvement roadmap"""
        # Identify dimensions that need improvement
        improvement_areas = [a for a in assessments if a.current_level != MaturityLevel.ADVANCED]
        
        # Sort by score (lowest first)
        improvement_areas.sort(key=lambda x: x.score)
        
        phases = []
        
        if overall_level == MaturityLevel.TRADITIONAL:
            phases = [
                {
                    "phase": 1,
                    "name": "Foundation Building",
                    "duration": "3-6 months",
                    "focus_areas": [a.name for a in improvement_areas[:3]],
                    "key_objectives": [
                        "Establish basic Zero Trust controls",
                        "Implement identity verification",
                        "Enable basic monitoring"
                    ]
                },
                {
                    "phase": 2,
                    "name": "Capability Expansion", 
                    "duration": "6-12 months",
                    "focus_areas": [a.name for a in improvement_areas[3:5]],
                    "key_objectives": [
                        "Expand Zero Trust coverage",
                        "Implement advanced controls",
                        "Enhance visibility"
                    ]
                },
                {
                    "phase": 3,
                    "name": "Optimization",
                    "duration": "12-18 months", 
                    "focus_areas": [a.name for a in improvement_areas[5:]],
                    "key_objectives": [
                        "Optimize all dimensions",
                        "Achieve advanced maturity",
                        "Continuous improvement"
                    ]
                }
            ]
        elif overall_level == MaturityLevel.INITIAL:
            phases = [
                {
                    "phase": 1,
                    "name": "Enhancement",
                    "duration": "3-6 months",
                    "focus_areas": [a.name for a in improvement_areas[:3]],
                    "key_objectives": [
                        "Strengthen existing controls",
                        "Address critical gaps",
                        "Improve monitoring"
                    ]
                },
                {
                    "phase": 2,
                    "name": "Advanced Implementation",
                    "duration": "6-12 months",
                    "focus_areas": [a.name for a in improvement_areas[3:]],
                    "key_objectives": [
                        "Implement advanced features",
                        "Achieve intermediate maturity",
                        "Establish governance"
                    ]
                }
            ]
        else:
            phases = [
                {
                    "phase": 1,
                    "name": "Optimization",
                    "duration": "3-6 months",
                    "focus_areas": [a.name for a in improvement_areas],
                    "key_objectives": [
                        "Fine-tune existing controls",
                        "Achieve advanced maturity",
                        "Implement automation"
                    ]
                }
            ]
        
        return {
            "current_level": overall_level.value,
            "target_level": MaturityLevel.ADVANCED.value,
            "phases": phases,
            "total_duration": f"{sum(int(p['duration'].split('-')[0]) for p in phases)}-{sum(int(p['duration'].split('-')[1].split()[0]) for p in phases)} months"
        }
    
    def _generate_benchmark_comparison(self, overall_score: float) -> Dict[str, Any]:
        """Generate benchmark comparison (simulated data)"""
        return {
            "your_score": overall_score,
            "industry_average": 45.0,
            "industry_leaders": 75.0,
            "percentile": min(95, max(5, int((overall_score / 100) * 100))),
            "comparison": "above_average" if overall_score > 45 else "below_average"
        }
    
    def _identify_improvement_priorities(self, assessments: List[MaturityDimension]) -> List[Dict[str, Any]]:
        """Identify top improvement priorities"""
        # Sort by score (lowest first) to identify priorities
        sorted_assessments = sorted(assessments, key=lambda x: x.score)
        
        priorities = []
        for i, assessment in enumerate(sorted_assessments[:5]):
            priorities.append({
                "rank": i + 1,
                "dimension": assessment.name,
                "current_score": assessment.score,
                "current_level": assessment.current_level.value,
                "improvement_potential": 100 - assessment.score,
                "key_gaps": assessment.gaps[:3],
                "immediate_actions": assessment.next_steps[:3]
            })
        
        return priorities
    
    def _dimension_to_dict(self, dimension: MaturityDimension) -> Dict[str, Any]:
        """Convert MaturityDimension to dictionary"""
        return {
            'name': dimension.name,
            'current_level': dimension.current_level.value,
            'score': dimension.score,
            'description': dimension.description,
            'strengths': dimension.strengths,
            'gaps': dimension.gaps,
            'next_steps': dimension.next_steps
        }
    
    def _define_maturity_criteria(self) -> Dict[str, Any]:
        """Define maturity criteria for each dimension (placeholder for future enhancement)"""
        return {}

