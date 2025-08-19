from flask import Blueprint, jsonify, request
from src.models.assessment import Assessment, Recommendation, IdentityRisk, PermissionRisk, ZeroTrustRoadmap, db
from datetime import datetime, timedelta
import json

roadmap_bp = Blueprint('roadmap', __name__)

def generate_roadmap_phases(assessment, recommendations):
    """Generate roadmap phases based on assessment results"""
    
    # Categorize recommendations by Zero Trust principles and priority
    critical_recs = [r for r in recommendations if r.priority == 'Critical']
    high_recs = [r for r in recommendations if r.priority == 'High']
    medium_recs = [r for r in recommendations if r.priority == 'Medium']
    
    # Define phases based on Zero Trust maturity progression
    phases = []
    
    # Phase 1: Foundation Security (0-3 months)
    phase1_tasks = []
    for rec in critical_recs:
        phase1_tasks.append({
            'task': rec.recommendation,
            'category': rec.category,
            'zero_trust_principle': rec.zero_trust_principle or 'Assume Breach',
            'estimated_effort': rec.estimated_effort or 'High',
            'affected_count': rec.affected_count,
            'implementation_steps': json.loads(rec.implementation_steps) if rec.implementation_steps else [],
            'recommendation_id': rec.id
        })
    
    # Add essential foundation tasks
    foundation_tasks = [
        {
            'task': 'Implement comprehensive logging and monitoring',
            'category': 'Security Monitoring',
            'zero_trust_principle': 'Assume Breach',
            'estimated_effort': 'Medium',
            'affected_count': 0,
            'implementation_steps': [
                'Deploy centralized logging solution',
                'Configure security event monitoring',
                'Establish baseline security metrics',
                'Create incident response procedures'
            ]
        },
        {
            'task': 'Establish identity governance framework',
            'category': 'Identity Management',
            'zero_trust_principle': 'Verify Explicitly',
            'estimated_effort': 'High',
            'affected_count': 0,
            'implementation_steps': [
                'Define identity lifecycle processes',
                'Implement access review procedures',
                'Establish role-based access controls',
                'Create identity risk assessment framework'
            ]
        }
    ]
    
    phase1_tasks.extend(foundation_tasks)
    
    phases.append({
        'phase_number': 1,
        'phase_name': 'Foundation Security',
        'duration': '0-3 months',
        'objective': 'Address critical security gaps and establish baseline security controls',
        'tasks': phase1_tasks,
        'deliverables': [
            'Critical security vulnerabilities remediated',
            'Basic access controls implemented',
            'Security monitoring baseline established',
            'Incident response procedures updated',
            'Identity governance framework defined'
        ],
        'success_criteria': [
            'All critical recommendations addressed',
            'Zero high-risk security findings',
            'Basic monitoring and alerting operational',
            'Identity lifecycle processes documented'
        ],
        'estimated_cost': '$50,000 - $100,000',
        'resource_requirements': [
            '1 Security Architect',
            '2 Security Engineers',
            'Security monitoring tools'
        ]
    })
    
    # Phase 2: Identity and Access Management (3-6 months)
    phase2_tasks = []
    identity_recs = [r for r in high_recs if 'identity' in r.category.lower() or 'access' in r.category.lower()]
    for rec in identity_recs:
        phase2_tasks.append({
            'task': rec.recommendation,
            'category': rec.category,
            'zero_trust_principle': rec.zero_trust_principle or 'Verify Explicitly',
            'estimated_effort': rec.estimated_effort or 'Medium',
            'affected_count': rec.affected_count,
            'implementation_steps': json.loads(rec.implementation_steps) if rec.implementation_steps else [],
            'recommendation_id': rec.id
        })
    
    # Add standard IAM tasks
    iam_tasks = [
        {
            'task': 'Implement multi-factor authentication for all privileged accounts',
            'category': 'Identity Security',
            'zero_trust_principle': 'Verify Explicitly',
            'estimated_effort': 'Medium',
            'affected_count': 0,
            'implementation_steps': [
                'Deploy MFA solution',
                'Configure MFA policies',
                'Train users on MFA usage',
                'Monitor MFA compliance'
            ]
        },
        {
            'task': 'Deploy privileged access management (PAM) solution',
            'category': 'Access Control',
            'zero_trust_principle': 'Use Least Privilege Access',
            'estimated_effort': 'High',
            'affected_count': 0,
            'implementation_steps': [
                'Select and deploy PAM platform',
                'Onboard privileged accounts',
                'Configure access policies',
                'Implement session monitoring'
            ]
        },
        {
            'task': 'Implement just-in-time (JIT) access controls',
            'category': 'Access Control',
            'zero_trust_principle': 'Use Least Privilege Access',
            'estimated_effort': 'Medium',
            'affected_count': 0,
            'implementation_steps': [
                'Design JIT access workflows',
                'Implement approval processes',
                'Configure automated provisioning',
                'Monitor access usage patterns'
            ]
        }
    ]
    
    phase2_tasks.extend(iam_tasks)
    
    phases.append({
        'phase_number': 2,
        'phase_name': 'Identity and Access Management',
        'duration': '3-6 months',
        'objective': 'Establish comprehensive identity verification and least privilege access controls',
        'tasks': phase2_tasks,
        'deliverables': [
            'MFA enabled for all privileged accounts',
            'PAM solution operational',
            'JIT access controls implemented',
            'Identity lifecycle management processes',
            'Regular access reviews implemented'
        ],
        'success_criteria': [
            '100% MFA compliance for privileged accounts',
            'Privileged access sessions monitored and recorded',
            'Automated identity provisioning and deprovisioning',
            'Access reviews completed quarterly'
        ],
        'estimated_cost': '$200,000 - $400,000',
        'resource_requirements': [
            '1 Identity Specialist',
            '2 Security Engineers',
            'PAM platform license',
            'MFA solution license'
        ]
    })
    
    # Phase 3: Data Protection and Network Security (6-9 months)
    phase3_tasks = []
    data_network_recs = [r for r in high_recs + medium_recs 
                        if any(keyword in r.category.lower() 
                              for keyword in ['data', 'network', 'permission', 'encryption'])]
    
    for rec in data_network_recs[:10]:  # Limit to top 10 recommendations
        phase3_tasks.append({
            'task': rec.recommendation,
            'category': rec.category,
            'zero_trust_principle': rec.zero_trust_principle or 'Assume Breach',
            'estimated_effort': rec.estimated_effort or 'Medium',
            'affected_count': rec.affected_count,
            'implementation_steps': json.loads(rec.implementation_steps) if rec.implementation_steps else [],
            'recommendation_id': rec.id
        })
    
    # Add standard data protection tasks
    data_protection_tasks = [
        {
            'task': 'Implement data classification and labeling',
            'category': 'Data Protection',
            'zero_trust_principle': 'Assume Breach',
            'estimated_effort': 'Medium',
            'affected_count': 0,
            'implementation_steps': [
                'Define data classification scheme',
                'Deploy data classification tools',
                'Train users on data handling',
                'Implement automated labeling'
            ]
        },
        {
            'task': 'Deploy data loss prevention (DLP) solution',
            'category': 'Data Protection',
            'zero_trust_principle': 'Assume Breach',
            'estimated_effort': 'High',
            'affected_count': 0,
            'implementation_steps': [
                'Select and deploy DLP platform',
                'Configure data protection policies',
                'Implement monitoring and alerting',
                'Train security team on DLP management'
            ]
        },
        {
            'task': 'Implement network micro-segmentation',
            'category': 'Network Security',
            'zero_trust_principle': 'Assume Breach',
            'estimated_effort': 'High',
            'affected_count': 0,
            'implementation_steps': [
                'Assess current network architecture',
                'Design segmentation strategy',
                'Implement network controls',
                'Monitor network traffic patterns'
            ]
        }
    ]
    
    phase3_tasks.extend(data_protection_tasks)
    
    phases.append({
        'phase_number': 3,
        'phase_name': 'Data Protection and Network Security',
        'duration': '6-9 months',
        'objective': 'Implement comprehensive data protection and network segmentation',
        'tasks': phase3_tasks,
        'deliverables': [
            'Data classification policies and procedures',
            'DLP solution protecting sensitive data',
            'Network micro-segmentation implemented',
            'Encryption at rest and in transit',
            'Data access controls enforced'
        ],
        'success_criteria': [
            'All sensitive data classified and protected',
            'Zero data loss incidents',
            'Network traffic properly segmented and monitored',
            'Data access logging operational'
        ],
        'estimated_cost': '$300,000 - $500,000',
        'resource_requirements': [
            '1 Data Protection Specialist',
            '1 Network Security Specialist',
            '2 Security Engineers',
            'DLP platform license',
            'Network segmentation tools'
        ]
    })
    
    # Phase 4: Advanced Monitoring and Analytics (9-12 months)
    phase4_tasks = []
    remaining_recs = [r for r in medium_recs 
                     if not any(keyword in r.category.lower() 
                               for keyword in ['identity', 'access', 'data', 'network', 'permission'])]
    
    for rec in remaining_recs[:8]:  # Limit to top 8 recommendations
        phase4_tasks.append({
            'task': rec.recommendation,
            'category': rec.category,
            'zero_trust_principle': rec.zero_trust_principle or 'Assume Breach',
            'estimated_effort': rec.estimated_effort or 'Medium',
            'affected_count': rec.affected_count,
            'implementation_steps': json.loads(rec.implementation_steps) if rec.implementation_steps else [],
            'recommendation_id': rec.id
        })
    
    # Add advanced monitoring tasks
    monitoring_tasks = [
        {
            'task': 'Deploy advanced threat detection and response',
            'category': 'Security Monitoring',
            'zero_trust_principle': 'Assume Breach',
            'estimated_effort': 'High',
            'affected_count': 0,
            'implementation_steps': [
                'Deploy SIEM/SOAR platform',
                'Configure threat detection rules',
                'Implement automated response workflows',
                'Train security operations team'
            ]
        },
        {
            'task': 'Implement user and entity behavior analytics (UEBA)',
            'category': 'Behavioral Analytics',
            'zero_trust_principle': 'Verify Explicitly',
            'estimated_effort': 'Medium',
            'affected_count': 0,
            'implementation_steps': [
                'Deploy UEBA solution',
                'Configure behavioral baselines',
                'Implement anomaly detection',
                'Integrate with incident response'
            ]
        },
        {
            'task': 'Establish continuous compliance monitoring',
            'category': 'Compliance',
            'zero_trust_principle': 'Verify Explicitly',
            'estimated_effort': 'Medium',
            'affected_count': 0,
            'implementation_steps': [
                'Deploy compliance monitoring tools',
                'Configure compliance policies',
                'Implement automated reporting',
                'Establish compliance dashboards'
            ]
        }
    ]
    
    phase4_tasks.extend(monitoring_tasks)
    
    phases.append({
        'phase_number': 4,
        'phase_name': 'Advanced Monitoring and Analytics',
        'duration': '9-12 months',
        'objective': 'Implement advanced security monitoring and continuous improvement',
        'tasks': phase4_tasks,
        'deliverables': [
            'Advanced threat detection operational',
            'UEBA solution analyzing user behavior',
            'Continuous compliance monitoring',
            'Automated incident response workflows',
            'Security analytics dashboards'
        ],
        'success_criteria': [
            'Mean time to detection (MTTD) < 1 hour',
            'Mean time to response (MTTR) < 4 hours',
            'Continuous compliance score > 95%',
            'Automated response to 80% of incidents'
        ],
        'estimated_cost': '$150,000 - $300,000',
        'resource_requirements': [
            '1 Security Analytics Specialist',
            '2 Security Operations Engineers',
            'SIEM/SOAR platform license',
            'UEBA solution license'
        ]
    })
    
    return phases

def generate_roadmap_milestones(phases):
    """Generate milestones based on phases"""
    milestones = []
    
    for i, phase in enumerate(phases):
        milestone_date = datetime.utcnow() + timedelta(days=90 * (i + 1))  # 3-month intervals
        
        milestones.append({
            'milestone': f"{phase['phase_name']} Completion",
            'target_date': milestone_date.strftime('%Y-%m-%d'),
            'description': phase['objective'],
            'success_criteria': phase['success_criteria'],
            'phase_number': phase['phase_number'],
            'deliverables': phase['deliverables']
        })
    
    return milestones

def generate_success_metrics(assessment):
    """Generate success metrics based on assessment results"""
    metrics = [
        {
            'metric': 'Zero Trust Maturity Score',
            'baseline': assessment.zero_trust_score or 0,
            'target': 90,
            'measurement': 'Quarterly assessment using ADZero Trust tool',
            'category': 'Overall Maturity'
        },
        {
            'metric': 'Critical Security Findings',
            'baseline': assessment.high_risk_items or 0,
            'target': 0,
            'measurement': 'Monthly security assessment',
            'category': 'Risk Reduction'
        },
        {
            'metric': 'MFA Compliance Rate',
            'baseline': 'TBD',
            'target': 100,
            'measurement': 'Monthly identity audit',
            'category': 'Identity Security'
        },
        {
            'metric': 'Privileged Account Monitoring',
            'baseline': 'TBD',
            'target': 100,
            'measurement': 'PAM system reporting',
            'category': 'Access Control'
        },
        {
            'metric': 'Data Classification Coverage',
            'baseline': 'TBD',
            'target': 95,
            'measurement': 'DLP system reporting',
            'category': 'Data Protection'
        },
        {
            'metric': 'Mean Time to Detection (MTTD)',
            'baseline': 'TBD',
            'target': '< 1 hour',
            'measurement': 'Security incident analysis',
            'category': 'Threat Detection'
        },
        {
            'metric': 'Mean Time to Response (MTTR)',
            'baseline': 'TBD',
            'target': '< 4 hours',
            'measurement': 'Security incident analysis',
            'category': 'Incident Response'
        },
        {
            'metric': 'Compliance Score',
            'baseline': 'TBD',
            'target': 95,
            'measurement': 'Continuous compliance monitoring',
            'category': 'Compliance'
        }
    ]
    
    return metrics

@roadmap_bp.route('/roadmap/assessments/<int:assessment_id>/generate', methods=['POST'])
def generate_roadmap(assessment_id):
    """Generate a Zero Trust implementation roadmap for an assessment"""
    try:
        assessment = Assessment.query.get_or_404(assessment_id)
        
        if assessment.status != 'completed':
            return jsonify({
                'success': False,
                'error': 'Assessment must be completed before generating roadmap'
            }), 400
        
        # Get assessment recommendations
        recommendations = Recommendation.query.filter_by(assessment_id=assessment_id).all()
        
        if not recommendations:
            return jsonify({
                'success': False,
                'error': 'No recommendations found for this assessment'
            }), 404
        
        # Get request parameters
        data = request.json or {}
        timeline_months = data.get('timeline_months', 12)
        priority_focus = data.get('priority_focus', 'Security')
        
        # Generate roadmap components
        phases = generate_roadmap_phases(assessment, recommendations)
        milestones = generate_roadmap_milestones(phases)
        success_metrics = generate_success_metrics(assessment)
        
        # Calculate resource requirements
        total_cost_min = sum([
            50000,   # Phase 1
            200000,  # Phase 2
            300000,  # Phase 3
            150000   # Phase 4
        ])
        total_cost_max = sum([
            100000,  # Phase 1
            400000,  # Phase 2
            500000,  # Phase 3
            300000   # Phase 4
        ])
        
        resource_requirements = {
            'personnel': {
                'security_architect': '1 FTE for 12 months',
                'security_engineer': '2-3 FTE for 12 months',
                'identity_specialist': '1 FTE for 6 months',
                'network_specialist': '1 FTE for 6 months',
                'data_protection_specialist': '1 FTE for 6 months',
                'compliance_specialist': '0.5 FTE for 12 months'
            },
            'technology': {
                'pam_solution': 'Enterprise PAM platform license and implementation',
                'siem_solution': 'SIEM/SOAR platform upgrade or new deployment',
                'dlp_solution': 'Data loss prevention platform',
                'ueba_solution': 'User and entity behavior analytics platform',
                'network_security': 'Network segmentation and monitoring tools',
                'mfa_solution': 'Multi-factor authentication platform'
            },
            'budget': {
                'phase_1': '$50,000 - $100,000',
                'phase_2': '$200,000 - $400,000',
                'phase_3': '$300,000 - $500,000',
                'phase_4': '$150,000 - $300,000',
                'total': f'${total_cost_min:,} - ${total_cost_max:,}'
            }
        }
        
        # Create roadmap record
        roadmap_name = f"Zero Trust Roadmap - {assessment.name}"
        roadmap_description = f"Comprehensive Zero Trust implementation roadmap for {assessment.domain} based on assessment findings"
        
        # Check if roadmap already exists
        existing_roadmap = ZeroTrustRoadmap.query.filter_by(assessment_id=assessment_id).first()
        
        if existing_roadmap:
            # Update existing roadmap
            roadmap = existing_roadmap
            roadmap.name = roadmap_name
            roadmap.description = roadmap_description
            roadmap.timeline_months = timeline_months
            roadmap.current_maturity = assessment.maturity_level or 'Traditional'
            roadmap.target_maturity = 'Advanced'
            roadmap.phases_json = json.dumps(phases)
            roadmap.milestones_json = json.dumps(milestones)
            roadmap.resources_json = json.dumps(resource_requirements)
            roadmap.metrics_json = json.dumps(success_metrics)
        else:
            # Create new roadmap
            roadmap = ZeroTrustRoadmap(
                assessment_id=assessment_id,
                name=roadmap_name,
                description=roadmap_description,
                timeline_months=timeline_months,
                current_maturity=assessment.maturity_level or 'Traditional',
                target_maturity='Advanced',
                phases_json=json.dumps(phases),
                milestones_json=json.dumps(milestones),
                resources_json=json.dumps(resource_requirements),
                metrics_json=json.dumps(success_metrics)
            )
            db.session.add(roadmap)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': roadmap.to_dict(),
            'message': 'Roadmap generated successfully'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@roadmap_bp.route('/roadmap/<int:roadmap_id>', methods=['GET'])
def get_roadmap(roadmap_id):
    """Get a specific roadmap"""
    try:
        roadmap = ZeroTrustRoadmap.query.get_or_404(roadmap_id)
        
        # Get associated assessment information
        assessment = Assessment.query.get(roadmap.assessment_id)
        
        roadmap_data = roadmap.to_dict()
        roadmap_data['assessment'] = {
            'id': assessment.id,
            'name': assessment.name,
            'domain': assessment.domain,
            'assessment_type': assessment.assessment_type,
            'zero_trust_score': assessment.zero_trust_score,
            'maturity_level': assessment.maturity_level,
            'completed_at': assessment.completed_at.isoformat() if assessment.completed_at else None
        }
        
        return jsonify({
            'success': True,
            'data': roadmap_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@roadmap_bp.route('/roadmap/assessments/<int:assessment_id>', methods=['GET'])
def get_roadmap_by_assessment(assessment_id):
    """Get roadmap for a specific assessment"""
    try:
        Assessment.query.get_or_404(assessment_id)  # Verify assessment exists
        
        roadmap = ZeroTrustRoadmap.query.filter_by(assessment_id=assessment_id).first()
        
        if not roadmap:
            return jsonify({
                'success': False,
                'error': 'No roadmap found for this assessment'
            }), 404
        
        return jsonify({
            'success': True,
            'data': roadmap.to_dict()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@roadmap_bp.route('/roadmap', methods=['GET'])
def get_all_roadmaps():
    """Get all roadmaps with optional filtering"""
    try:
        # Query parameters
        limit = request.args.get('limit', type=int)
        assessment_id = request.args.get('assessment_id', type=int)
        
        query = ZeroTrustRoadmap.query
        
        if assessment_id:
            query = query.filter_by(assessment_id=assessment_id)
        
        # Order by creation date (newest first)
        query = query.order_by(ZeroTrustRoadmap.created_at.desc())
        
        if limit:
            query = query.limit(limit)
        
        roadmaps = query.all()
        
        # Add assessment information to each roadmap
        roadmap_data = []
        for roadmap in roadmaps:
            assessment = Assessment.query.get(roadmap.assessment_id)
            roadmap_dict = roadmap.to_dict()
            roadmap_dict['assessment'] = {
                'name': assessment.name if assessment else 'Unknown',
                'domain': assessment.domain if assessment else 'Unknown',
                'assessment_type': assessment.assessment_type if assessment else 'Unknown'
            }
            roadmap_data.append(roadmap_dict)
        
        return jsonify({
            'success': True,
            'data': roadmap_data,
            'count': len(roadmap_data)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@roadmap_bp.route('/roadmap/<int:roadmap_id>', methods=['PUT'])
def update_roadmap(roadmap_id):
    """Update a roadmap"""
    try:
        roadmap = ZeroTrustRoadmap.query.get_or_404(roadmap_id)
        data = request.json
        
        # Update allowed fields
        if 'name' in data:
            roadmap.name = data['name']
        if 'description' in data:
            roadmap.description = data['description']
        if 'timeline_months' in data:
            roadmap.timeline_months = data['timeline_months']
        if 'target_maturity' in data:
            roadmap.target_maturity = data['target_maturity']
        if 'phases' in data:
            roadmap.phases_json = json.dumps(data['phases'])
        if 'milestones' in data:
            roadmap.milestones_json = json.dumps(data['milestones'])
        if 'resources' in data:
            roadmap.resources_json = json.dumps(data['resources'])
        if 'metrics' in data:
            roadmap.metrics_json = json.dumps(data['metrics'])
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': roadmap.to_dict(),
            'message': 'Roadmap updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@roadmap_bp.route('/roadmap/<int:roadmap_id>', methods=['DELETE'])
def delete_roadmap(roadmap_id):
    """Delete a roadmap"""
    try:
        roadmap = ZeroTrustRoadmap.query.get_or_404(roadmap_id)
        
        db.session.delete(roadmap)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Roadmap deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@roadmap_bp.route('/roadmap/<int:roadmap_id>/export', methods=['GET'])
def export_roadmap(roadmap_id):
    """Export roadmap in various formats"""
    try:
        roadmap = ZeroTrustRoadmap.query.get_or_404(roadmap_id)
        assessment = Assessment.query.get(roadmap.assessment_id)
        
        export_format = request.args.get('format', 'json')  # json, markdown
        
        if export_format == 'markdown':
            # Generate Markdown export
            phases = json.loads(roadmap.phases_json) if roadmap.phases_json else []
            milestones = json.loads(roadmap.milestones_json) if roadmap.milestones_json else []
            resources = json.loads(roadmap.resources_json) if roadmap.resources_json else {}
            metrics = json.loads(roadmap.metrics_json) if roadmap.metrics_json else []
            
            markdown_content = f"""# {roadmap.name}

**Generated:** {roadmap.created_at.strftime('%Y-%m-%d %H:%M:%S')}  
**Assessment:** {assessment.name if assessment else 'Unknown'}  
**Domain:** {assessment.domain if assessment else 'Unknown'}  
**Current Maturity:** {roadmap.current_maturity}  
**Target Maturity:** {roadmap.target_maturity}  
**Timeline:** {roadmap.timeline_months} months

## Description

{roadmap.description}

## Implementation Phases

"""
            
            for phase in phases:
                markdown_content += f"""### Phase {phase['phase_number']}: {phase['phase_name']}

**Duration:** {phase['duration']}  
**Objective:** {phase['objective']}

**Key Tasks:**
"""
                for task in phase.get('tasks', []):
                    markdown_content += f"- {task['task']} ({task['category']})\n"
                
                markdown_content += f"""
**Deliverables:**
"""
                for deliverable in phase.get('deliverables', []):
                    markdown_content += f"- {deliverable}\n"
                
                markdown_content += f"""
**Success Criteria:**
"""
                for criterion in phase.get('success_criteria', []):
                    markdown_content += f"- {criterion}\n"
                
                markdown_content += f"""
**Estimated Cost:** {phase.get('estimated_cost', 'TBD')}

"""
            
            markdown_content += """## Milestones

"""
            for milestone in milestones:
                markdown_content += f"""### {milestone['milestone']}

**Target Date:** {milestone['target_date']}  
**Description:** {milestone['description']}

**Success Criteria:**
"""
                for criterion in milestone.get('success_criteria', []):
                    markdown_content += f"- {criterion}\n"
                
                markdown_content += "\n"
            
            markdown_content += """## Resource Requirements

### Personnel
"""
            if 'personnel' in resources:
                for role, requirement in resources['personnel'].items():
                    markdown_content += f"- **{role.replace('_', ' ').title()}:** {requirement}\n"
            
            markdown_content += """
### Technology
"""
            if 'technology' in resources:
                for tech, requirement in resources['technology'].items():
                    markdown_content += f"- **{tech.replace('_', ' ').title()}:** {requirement}\n"
            
            markdown_content += """
### Budget
"""
            if 'budget' in resources:
                for phase, cost in resources['budget'].items():
                    markdown_content += f"- **{phase.replace('_', ' ').title()}:** {cost}\n"
            
            markdown_content += """
## Success Metrics

"""
            for metric in metrics:
                markdown_content += f"""### {metric['metric']}

- **Baseline:** {metric['baseline']}
- **Target:** {metric['target']}
- **Measurement:** {metric['measurement']}
- **Category:** {metric['category']}

"""
            
            markdown_content += """---
*Roadmap generated by ADZero Trust - A community contribution by Moazzam Jafri*
"""
            
            return jsonify({
                'success': True,
                'data': {
                    'format': 'markdown',
                    'content': markdown_content,
                    'filename': f"adzero_roadmap_{roadmap_id}.md"
                }
            })
        
        else:
            # Default JSON export
            return jsonify({
                'success': True,
                'data': {
                    'format': 'json',
                    'content': roadmap.to_dict(),
                    'filename': f"adzero_roadmap_{roadmap_id}.json"
                }
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

