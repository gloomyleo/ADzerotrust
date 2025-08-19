from flask import Blueprint, jsonify, request
from src.models.assessment import Assessment, AssessmentModule, Recommendation, IdentityRisk, PermissionRisk, ZeroTrustRoadmap, db
from sqlalchemy import func, desc
from datetime import datetime, timedelta
import json

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard/overview', methods=['GET'])
def get_dashboard_overview():
    """Get high-level dashboard overview statistics"""
    try:
        # Get total counts
        total_assessments = Assessment.query.count()
        completed_assessments = Assessment.query.filter_by(status='completed').count()
        running_assessments = Assessment.query.filter_by(status='running').count()
        failed_assessments = Assessment.query.filter_by(status='failed').count()
        
        # Get recent assessments (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_assessments = Assessment.query.filter(Assessment.created_at >= thirty_days_ago).count()
        
        # Get average Zero Trust score
        avg_zt_score = db.session.query(func.avg(Assessment.zero_trust_score)).filter(
            Assessment.zero_trust_score > 0
        ).scalar() or 0
        
        # Get total recommendations by priority
        total_recommendations = Recommendation.query.count()
        critical_recommendations = Recommendation.query.filter_by(priority='Critical').count()
        high_recommendations = Recommendation.query.filter_by(priority='High').count()
        
        # Get total risks
        total_identity_risks = IdentityRisk.query.count()
        high_identity_risks = IdentityRisk.query.filter_by(risk_level='High').count()
        total_permission_risks = PermissionRisk.query.count()
        high_permission_risks = PermissionRisk.query.filter_by(risk_level='High').count()
        
        # Get maturity distribution
        maturity_distribution = db.session.query(
            Assessment.maturity_level,
            func.count(Assessment.id)
        ).filter(
            Assessment.maturity_level.isnot(None)
        ).group_by(Assessment.maturity_level).all()
        
        maturity_stats = {}
        for level, count in maturity_distribution:
            maturity_stats[level] = count
        
        overview = {
            'assessments': {
                'total': total_assessments,
                'completed': completed_assessments,
                'running': running_assessments,
                'failed': failed_assessments,
                'recent': recent_assessments,
                'completion_rate': (completed_assessments / total_assessments * 100) if total_assessments > 0 else 0
            },
            'zero_trust': {
                'average_score': round(avg_zt_score, 2),
                'maturity_distribution': maturity_stats
            },
            'recommendations': {
                'total': total_recommendations,
                'critical': critical_recommendations,
                'high': high_recommendations,
                'medium': Recommendation.query.filter_by(priority='Medium').count(),
                'low': Recommendation.query.filter_by(priority='Low').count()
            },
            'risks': {
                'identity_risks': {
                    'total': total_identity_risks,
                    'high': high_identity_risks,
                    'medium': IdentityRisk.query.filter_by(risk_level='Medium').count(),
                    'low': IdentityRisk.query.filter_by(risk_level='Low').count()
                },
                'permission_risks': {
                    'total': total_permission_risks,
                    'high': high_permission_risks,
                    'medium': PermissionRisk.query.filter_by(risk_level='Medium').count(),
                    'low': PermissionRisk.query.filter_by(risk_level='Low').count()
                }
            }
        }
        
        return jsonify({
            'success': True,
            'data': overview
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/assessments/recent', methods=['GET'])
def get_recent_assessments():
    """Get recent assessments with summary information"""
    try:
        limit = request.args.get('limit', 10, type=int)
        
        assessments = Assessment.query.order_by(desc(Assessment.created_at)).limit(limit).all()
        
        assessment_data = []
        for assessment in assessments:
            # Get module completion status
            modules = AssessmentModule.query.filter_by(assessment_id=assessment.id).all()
            completed_modules = len([m for m in modules if m.status == 'completed'])
            total_modules = len(modules)
            
            # Get recommendation counts
            recommendations = Recommendation.query.filter_by(assessment_id=assessment.id).all()
            critical_recs = len([r for r in recommendations if r.priority == 'Critical'])
            high_recs = len([r for r in recommendations if r.priority == 'High'])
            
            assessment_info = assessment.to_dict()
            assessment_info.update({
                'module_progress': {
                    'completed': completed_modules,
                    'total': total_modules,
                    'percentage': (completed_modules / total_modules * 100) if total_modules > 0 else 0
                },
                'critical_recommendations': critical_recs,
                'high_recommendations': high_recs,
                'total_recommendations': len(recommendations)
            })
            
            assessment_data.append(assessment_info)
        
        return jsonify({
            'success': True,
            'data': assessment_data,
            'count': len(assessment_data)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/trends', methods=['GET'])
def get_dashboard_trends():
    """Get trend data for dashboard charts"""
    try:
        days = request.args.get('days', 30, type=int)
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Assessment creation trends
        assessment_trends = db.session.query(
            func.date(Assessment.created_at).label('date'),
            func.count(Assessment.id).label('count')
        ).filter(
            Assessment.created_at >= start_date
        ).group_by(
            func.date(Assessment.created_at)
        ).order_by('date').all()
        
        # Zero Trust score trends (by completion date)
        score_trends = db.session.query(
            func.date(Assessment.completed_at).label('date'),
            func.avg(Assessment.zero_trust_score).label('avg_score')
        ).filter(
            Assessment.completed_at >= start_date,
            Assessment.zero_trust_score > 0
        ).group_by(
            func.date(Assessment.completed_at)
        ).order_by('date').all()
        
        # Risk trends
        risk_trends = db.session.query(
            func.date(IdentityRisk.id).label('date'),  # Using ID creation as proxy for date
            func.count(IdentityRisk.id).label('identity_risks'),
            func.count(PermissionRisk.id).label('permission_risks')
        ).outerjoin(
            PermissionRisk, func.date(IdentityRisk.id) == func.date(PermissionRisk.id)
        ).group_by(
            func.date(IdentityRisk.id)
        ).order_by('date').all()
        
        # Format trends data
        trends = {
            'assessments': [
                {
                    'date': trend.date.isoformat(),
                    'count': trend.count
                } for trend in assessment_trends
            ],
            'zero_trust_scores': [
                {
                    'date': trend.date.isoformat(),
                    'average_score': round(trend.avg_score, 2)
                } for trend in score_trends
            ],
            'risks': [
                {
                    'date': trend.date.isoformat(),
                    'identity_risks': trend.identity_risks,
                    'permission_risks': trend.permission_risks or 0
                } for trend in risk_trends
            ]
        }
        
        return jsonify({
            'success': True,
            'data': trends,
            'period_days': days
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/risks/top', methods=['GET'])
def get_top_risks():
    """Get top risks across all assessments"""
    try:
        limit = request.args.get('limit', 20, type=int)
        risk_type = request.args.get('type', 'all')  # all, identity, permission
        
        risks = []
        
        if risk_type in ['all', 'identity']:
            # Get top identity risks
            identity_risks = IdentityRisk.query.filter_by(risk_level='High').order_by(
                desc(IdentityRisk.risk_score)
            ).limit(limit).all()
            
            for risk in identity_risks:
                assessment = Assessment.query.get(risk.assessment_id)
                risks.append({
                    'type': 'identity',
                    'id': risk.id,
                    'assessment_id': risk.assessment_id,
                    'assessment_name': assessment.name if assessment else 'Unknown',
                    'domain': assessment.domain if assessment else 'Unknown',
                    'identity_name': risk.identity_name,
                    'identity_type': risk.identity_type,
                    'risk_score': risk.risk_score,
                    'risk_level': risk.risk_level,
                    'risk_factors': json.loads(risk.risk_factors) if risk.risk_factors else [],
                    'is_privileged': risk.is_privileged,
                    'is_stale': risk.is_stale,
                    'mfa_enabled': risk.mfa_enabled
                })
        
        if risk_type in ['all', 'permission']:
            # Get top permission risks
            permission_risks = PermissionRisk.query.filter_by(risk_level='High').order_by(
                desc(PermissionRisk.risk_score)
            ).limit(limit).all()
            
            for risk in permission_risks:
                assessment = Assessment.query.get(risk.assessment_id)
                risks.append({
                    'type': 'permission',
                    'id': risk.id,
                    'assessment_id': risk.assessment_id,
                    'assessment_name': assessment.name if assessment else 'Unknown',
                    'domain': assessment.domain if assessment else 'Unknown',
                    'resource_path': risk.resource_path,
                    'resource_type': risk.resource_type,
                    'risk_score': risk.risk_score,
                    'risk_level': risk.risk_level,
                    'risk_factors': json.loads(risk.risk_factors) if risk.risk_factors else [],
                    'has_anonymous_access': risk.has_anonymous_access,
                    'has_broad_access': risk.has_broad_access,
                    'has_full_control': risk.has_full_control,
                    'owner': risk.owner
                })
        
        # Sort by risk score
        risks.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return jsonify({
            'success': True,
            'data': risks[:limit],
            'count': len(risks[:limit]),
            'risk_type': risk_type
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/recommendations/priority', methods=['GET'])
def get_priority_recommendations():
    """Get recommendations grouped by priority"""
    try:
        status_filter = request.args.get('status', 'open')  # open, all
        limit = request.args.get('limit', 50, type=int)
        
        query = Recommendation.query
        if status_filter != 'all':
            query = query.filter_by(status=status_filter)
        
        # Get recommendations grouped by priority
        recommendations = query.order_by(
            db.case(
                [(Recommendation.priority == 'Critical', 1),
                 (Recommendation.priority == 'High', 2),
                 (Recommendation.priority == 'Medium', 3),
                 (Recommendation.priority == 'Low', 4)],
                else_=5
            ),
            desc(Recommendation.affected_count)
        ).limit(limit).all()
        
        # Group by priority
        grouped_recommendations = {
            'Critical': [],
            'High': [],
            'Medium': [],
            'Low': []
        }
        
        for rec in recommendations:
            assessment = Assessment.query.get(rec.assessment_id)
            rec_data = rec.to_dict()
            rec_data.update({
                'assessment_name': assessment.name if assessment else 'Unknown',
                'domain': assessment.domain if assessment else 'Unknown'
            })
            
            if rec.priority in grouped_recommendations:
                grouped_recommendations[rec.priority].append(rec_data)
        
        # Calculate summary statistics
        summary = {
            'total': len(recommendations),
            'by_priority': {
                priority: len(recs) for priority, recs in grouped_recommendations.items()
            },
            'by_status': {}
        }
        
        # Get status distribution
        status_distribution = db.session.query(
            Recommendation.status,
            func.count(Recommendation.id)
        ).group_by(Recommendation.status).all()
        
        for status, count in status_distribution:
            summary['by_status'][status] = count
        
        return jsonify({
            'success': True,
            'data': grouped_recommendations,
            'summary': summary
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/compliance', methods=['GET'])
def get_compliance_overview():
    """Get compliance overview across all assessments"""
    try:
        # Get latest assessment for each domain
        latest_assessments = db.session.query(
            Assessment.domain,
            func.max(Assessment.id).label('latest_id')
        ).filter(
            Assessment.status == 'completed'
        ).group_by(Assessment.domain).all()
        
        compliance_data = []
        overall_scores = {
            'zero_trust': [],
            'nist': [],
            'cis': [],
            'iso27001': []
        }
        
        for domain, assessment_id in latest_assessments:
            assessment = Assessment.query.get(assessment_id)
            if assessment:
                # Get compliance information from modules
                modules = AssessmentModule.query.filter_by(assessment_id=assessment_id).all()
                
                compliance_info = {
                    'domain': domain,
                    'assessment_id': assessment_id,
                    'assessment_name': assessment.name,
                    'zero_trust_score': assessment.zero_trust_score or 0,
                    'maturity_level': assessment.maturity_level or 'Unknown',
                    'completed_at': assessment.completed_at.isoformat() if assessment.completed_at else None,
                    'frameworks': {
                        'nist': {'score': 0, 'status': 'Unknown'},
                        'cis': {'score': 0, 'status': 'Unknown'},
                        'iso27001': {'score': 0, 'status': 'Unknown'}
                    }
                }
                
                # Extract compliance scores from SecurityAuditor results
                security_module = next((m for m in modules if m.module_name == 'SecurityAuditor'), None)
                if security_module and security_module.results_json:
                    try:
                        results = json.loads(security_module.results_json)
                        if 'ComplianceChecks' in results:
                            compliance_checks = results['ComplianceChecks']
                            
                            for framework in ['NIST', 'CIS', 'ISO27001']:
                                if framework in compliance_checks:
                                    score = compliance_checks[framework].get('OverallScore', 0)
                                    compliance_info['frameworks'][framework.lower()] = {
                                        'score': score,
                                        'status': 'Compliant' if score >= 80 else 'Partially Compliant' if score >= 60 else 'Non-Compliant'
                                    }
                                    overall_scores[framework.lower()].append(score)
                    except json.JSONDecodeError:
                        pass
                
                overall_scores['zero_trust'].append(assessment.zero_trust_score or 0)
                compliance_data.append(compliance_info)
        
        # Calculate overall statistics
        overall_stats = {}
        for framework, scores in overall_scores.items():
            if scores:
                overall_stats[framework] = {
                    'average_score': round(sum(scores) / len(scores), 2),
                    'min_score': min(scores),
                    'max_score': max(scores),
                    'compliant_count': len([s for s in scores if s >= 80]),
                    'total_count': len(scores)
                }
            else:
                overall_stats[framework] = {
                    'average_score': 0,
                    'min_score': 0,
                    'max_score': 0,
                    'compliant_count': 0,
                    'total_count': 0
                }
        
        return jsonify({
            'success': True,
            'data': {
                'domains': compliance_data,
                'overall_statistics': overall_stats,
                'summary': {
                    'total_domains': len(compliance_data),
                    'average_zero_trust_score': overall_stats['zero_trust']['average_score'],
                    'compliant_domains': overall_stats['zero_trust']['compliant_count']
                }
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/analytics/identity', methods=['GET'])
def get_identity_analytics():
    """Get identity-focused analytics"""
    try:
        # Get identity type distribution
        identity_type_dist = db.session.query(
            IdentityRisk.identity_type,
            func.count(IdentityRisk.id)
        ).group_by(IdentityRisk.identity_type).all()
        
        # Get privileged account statistics
        privileged_stats = db.session.query(
            IdentityRisk.is_privileged,
            IdentityRisk.risk_level,
            func.count(IdentityRisk.id)
        ).group_by(
            IdentityRisk.is_privileged,
            IdentityRisk.risk_level
        ).all()
        
        # Get stale account statistics
        stale_stats = db.session.query(
            IdentityRisk.is_stale,
            IdentityRisk.risk_level,
            func.count(IdentityRisk.id)
        ).group_by(
            IdentityRisk.is_stale,
            IdentityRisk.risk_level
        ).all()
        
        # Get MFA statistics
        mfa_stats = db.session.query(
            IdentityRisk.mfa_enabled,
            IdentityRisk.is_privileged,
            func.count(IdentityRisk.id)
        ).group_by(
            IdentityRisk.mfa_enabled,
            IdentityRisk.is_privileged
        ).all()
        
        # Format analytics data
        analytics = {
            'identity_types': {
                item.identity_type: item[1] for item in identity_type_dist
            },
            'privileged_accounts': {
                'privileged_high_risk': 0,
                'privileged_medium_risk': 0,
                'privileged_low_risk': 0,
                'non_privileged_high_risk': 0,
                'non_privileged_medium_risk': 0,
                'non_privileged_low_risk': 0
            },
            'stale_accounts': {
                'stale_high_risk': 0,
                'stale_medium_risk': 0,
                'stale_low_risk': 0,
                'active_high_risk': 0,
                'active_medium_risk': 0,
                'active_low_risk': 0
            },
            'mfa_compliance': {
                'privileged_with_mfa': 0,
                'privileged_without_mfa': 0,
                'non_privileged_with_mfa': 0,
                'non_privileged_without_mfa': 0
            }
        }
        
        # Process privileged account stats
        for is_privileged, risk_level, count in privileged_stats:
            key = f"{'privileged' if is_privileged else 'non_privileged'}_{risk_level.lower()}_risk"
            analytics['privileged_accounts'][key] = count
        
        # Process stale account stats
        for is_stale, risk_level, count in stale_stats:
            key = f"{'stale' if is_stale else 'active'}_{risk_level.lower()}_risk"
            analytics['stale_accounts'][key] = count
        
        # Process MFA stats
        for mfa_enabled, is_privileged, count in mfa_stats:
            key = f"{'privileged' if is_privileged else 'non_privileged'}_{'with' if mfa_enabled else 'without'}_mfa"
            analytics['mfa_compliance'][key] = count
        
        return jsonify({
            'success': True,
            'data': analytics
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/analytics/permissions', methods=['GET'])
def get_permission_analytics():
    """Get permission-focused analytics"""
    try:
        # Get resource type distribution
        resource_type_dist = db.session.query(
            PermissionRisk.resource_type,
            func.count(PermissionRisk.id)
        ).group_by(PermissionRisk.resource_type).all()
        
        # Get risk factor statistics
        anonymous_access = PermissionRisk.query.filter_by(has_anonymous_access=True).count()
        broad_access = PermissionRisk.query.filter_by(has_broad_access=True).count()
        full_control = PermissionRisk.query.filter_by(has_full_control=True).count()
        
        # Get risk level by resource type
        risk_by_type = db.session.query(
            PermissionRisk.resource_type,
            PermissionRisk.risk_level,
            func.count(PermissionRisk.id)
        ).group_by(
            PermissionRisk.resource_type,
            PermissionRisk.risk_level
        ).all()
        
        # Format analytics data
        analytics = {
            'resource_types': {
                item.resource_type: item[1] for item in resource_type_dist
            },
            'risk_factors': {
                'anonymous_access': anonymous_access,
                'broad_access': broad_access,
                'full_control': full_control,
                'total_permissions': PermissionRisk.query.count()
            },
            'risk_by_type': {}
        }
        
        # Process risk by type
        for resource_type, risk_level, count in risk_by_type:
            if resource_type not in analytics['risk_by_type']:
                analytics['risk_by_type'][resource_type] = {}
            analytics['risk_by_type'][resource_type][risk_level.lower()] = count
        
        return jsonify({
            'success': True,
            'data': analytics
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

