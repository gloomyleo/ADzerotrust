from flask import Blueprint, jsonify, request
from src.models.assessment import Assessment, AssessmentModule, Recommendation, IdentityRisk, PermissionRisk, db
import subprocess
import json
import os
import threading
from datetime import datetime
import tempfile
import logging

powershell_bp = Blueprint('powershell', __name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# PowerShell script paths (relative to project root)
POWERSHELL_SCRIPTS = {
    'ADInfoGatherer': '../../../PowerShell/Modules/AD-InfoGatherer.ps1',
    'IdentityAnalyzer': '../../../PowerShell/Modules/Identity-Analyzer.ps1',
    'PermissionAssessor': '../../../PowerShell/Modules/Permission-Assessor.ps1',
    'SecurityAuditor': '../../../PowerShell/Modules/Security-Auditor.ps1'
}

def get_script_path(script_name):
    """Get the absolute path to a PowerShell script"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        script_relative_path = POWERSHELL_SCRIPTS.get(script_name)
        if script_relative_path:
            script_path = os.path.join(current_dir, script_relative_path)
            script_path = os.path.normpath(script_path)
            return script_path
        return None
    except Exception as e:
        logger.error(f"Error getting script path for {script_name}: {str(e)}")
        return None

def execute_powershell_script(script_path, parameters=None, timeout=3600):
    """Execute a PowerShell script with parameters"""
    try:
        # Build PowerShell command
        cmd = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path]
        
        # Add parameters
        if parameters:
            for key, value in parameters.items():
                if value is not None:
                    if isinstance(value, bool):
                        if value:
                            cmd.extend([f'-{key}'])
                    else:
                        cmd.extend([f'-{key}', str(value)])
        
        logger.info(f"Executing PowerShell command: {' '.join(cmd)}")
        
        # Execute the script
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=os.path.dirname(script_path)
        )
        
        return {
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
        
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Script execution timed out',
            'timeout': True
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def parse_powershell_results(stdout, stderr):
    """Parse PowerShell script results"""
    try:
        # Try to find JSON output in stdout
        lines = stdout.split('\n')
        json_content = None
        
        # Look for JSON content (usually at the end of output)
        for i, line in enumerate(lines):
            if line.strip().startswith('{'):
                # Try to parse from this line to the end
                json_text = '\n'.join(lines[i:])
                try:
                    json_content = json.loads(json_text)
                    break
                except json.JSONDecodeError:
                    continue
        
        if json_content:
            return {
                'success': True,
                'data': json_content,
                'logs': '\n'.join(lines[:i]) if json_content else stdout
            }
        else:
            # No JSON found, return raw output
            return {
                'success': False,
                'error': 'No valid JSON output found',
                'raw_output': stdout,
                'stderr': stderr
            }
            
    except Exception as e:
        return {
            'success': False,
            'error': f'Error parsing results: {str(e)}',
            'raw_output': stdout,
            'stderr': stderr
        }

def process_assessment_results(assessment_id, module_name, results_data):
    """Process and store assessment results in the database"""
    try:
        # Update module with results
        module = AssessmentModule.query.filter_by(
            assessment_id=assessment_id,
            module_name=module_name
        ).first()
        
        if not module:
            logger.error(f"Module {module_name} not found for assessment {assessment_id}")
            return False
        
        # Store results
        module.results_json = json.dumps(results_data)
        module.status = 'completed'
        module.completed_at = datetime.utcnow()
        
        # Extract summary metrics based on module type
        if module_name == 'ADInfoGatherer':
            if 'Summary' in results_data:
                summary = results_data['Summary']
                module.items_analyzed = summary.get('TotalUsers', 0)
                module.high_risk_count = summary.get('HighRiskRecommendations', 0)
                module.medium_risk_count = summary.get('MediumRiskRecommendations', 0)
        
        elif module_name == 'IdentityAnalyzer':
            if 'IdentityRiskMatrix' in results_data:
                risk_matrix = results_data['IdentityRiskMatrix']
                module.items_analyzed = risk_matrix.get('TotalIdentities', 0)
                module.high_risk_count = risk_matrix.get('HighRiskCount', 0)
                module.medium_risk_count = risk_matrix.get('MediumRiskCount', 0)
                module.low_risk_count = risk_matrix.get('LowRiskCount', 0)
                
                # Store individual identity risks
                if 'HighRiskIdentities' in risk_matrix:
                    for identity in risk_matrix['HighRiskIdentities']:
                        identity_risk = IdentityRisk(
                            assessment_id=assessment_id,
                            identity_name=identity.get('SamAccountName', ''),
                            identity_type=identity.get('IdentityType', 'Unknown'),
                            risk_score=identity.get('RiskScore', 0),
                            risk_level='High',
                            risk_factors=json.dumps(identity.get('RiskFactors', [])),
                            is_privileged=identity.get('IsPrivileged', False),
                            is_stale='StaleAccount' in identity.get('RiskFactors', []),
                            mfa_enabled=identity.get('MFAEnabled', False),
                            groups_json=json.dumps(identity.get('Groups', []))
                        )
                        db.session.add(identity_risk)
        
        elif module_name == 'PermissionAssessor':
            if 'PermissionRiskMatrix' in results_data:
                risk_matrix = results_data['PermissionRiskMatrix']
                module.items_analyzed = risk_matrix.get('TotalPermissionsAnalyzed', 0)
                module.high_risk_count = risk_matrix.get('HighRiskCount', 0)
                module.medium_risk_count = risk_matrix.get('MediumRiskCount', 0)
                module.low_risk_count = risk_matrix.get('LowRiskCount', 0)
                
                # Store permission risks
                if 'HighRiskPermissions' in risk_matrix:
                    for permission in risk_matrix['HighRiskPermissions']:
                        permission_risk = PermissionRisk(
                            assessment_id=assessment_id,
                            resource_path=permission.get('Path', ''),
                            resource_type='FileSystem',  # Default, could be enhanced
                            risk_score=permission.get('RiskScore', 0),
                            risk_level='High',
                            risk_factors=json.dumps(permission.get('RiskFactors', [])),
                            has_anonymous_access='AnonymousAccess' in permission.get('RiskFactors', []),
                            has_broad_access='BroadAccess' in permission.get('RiskFactors', []),
                            has_full_control='FullControlAccess' in permission.get('RiskFactors', []),
                            owner=permission.get('Owner', ''),
                            permissions_json=json.dumps(permission.get('AccessRules', []))
                        )
                        db.session.add(permission_risk)
        
        elif module_name == 'SecurityAuditor':
            if 'SecurityBaseline' in results_data:
                baseline = results_data['SecurityBaseline']
                if 'WindowsSecurityBaseline' in baseline:
                    wsb = baseline['WindowsSecurityBaseline']
                    module.items_analyzed = wsb.get('TotalFeatures', 0)
                    compliant_features = wsb.get('CompliantFeatures', 0)
                    total_features = wsb.get('TotalFeatures', 1)
                    module.high_risk_count = total_features - compliant_features
        
        # Process recommendations
        if 'Recommendations' in results_data:
            for rec_data in results_data['Recommendations']:
                recommendation = Recommendation(
                    assessment_id=assessment_id,
                    category=rec_data.get('Category', 'General'),
                    priority=rec_data.get('Priority', 'Medium'),
                    issue=rec_data.get('Issue', ''),
                    recommendation=rec_data.get('Recommendation', ''),
                    zero_trust_principle=rec_data.get('ZeroTrustPrinciple', ''),
                    implementation_steps=json.dumps(rec_data.get('Implementation', [])),
                    affected_count=rec_data.get('AffectedCount', 0),
                    estimated_effort=rec_data.get('EstimatedEffort', 'Medium')
                )
                db.session.add(recommendation)
        
        db.session.commit()
        logger.info(f"Successfully processed results for {module_name}")
        return True
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing results for {module_name}: {str(e)}")
        return False

def run_assessment_module_async(assessment_id, module_id, module_name, parameters):
    """Run assessment module asynchronously"""
    try:
        # Update module status
        module = AssessmentModule.query.get(module_id)
        if not module:
            logger.error(f"Module {module_id} not found")
            return
        
        module.status = 'running'
        module.started_at = datetime.utcnow()
        db.session.commit()
        
        # Get script path
        script_path = get_script_path(module_name)
        if not script_path or not os.path.exists(script_path):
            module.status = 'failed'
            module.error_message = f'Script not found: {script_path}'
            db.session.commit()
            logger.error(f"Script not found for {module_name}: {script_path}")
            return
        
        # Execute PowerShell script
        logger.info(f"Starting {module_name} execution for assessment {assessment_id}")
        result = execute_powershell_script(script_path, parameters)
        
        if result['success']:
            # Parse results
            parsed_results = parse_powershell_results(result['stdout'], result['stderr'])
            
            if parsed_results['success']:
                # Process and store results
                if process_assessment_results(assessment_id, module_name, parsed_results['data']):
                    logger.info(f"Successfully completed {module_name} for assessment {assessment_id}")
                else:
                    module.status = 'failed'
                    module.error_message = 'Failed to process results'
                    db.session.commit()
            else:
                module.status = 'failed'
                module.error_message = parsed_results['error']
                db.session.commit()
                logger.error(f"Failed to parse results for {module_name}: {parsed_results['error']}")
        else:
            module.status = 'failed'
            module.error_message = result.get('error', 'Script execution failed')
            db.session.commit()
            logger.error(f"Script execution failed for {module_name}: {result.get('error', 'Unknown error')}")
        
    except Exception as e:
        try:
            module = AssessmentModule.query.get(module_id)
            if module:
                module.status = 'failed'
                module.error_message = str(e)
                db.session.commit()
        except:
            pass
        logger.error(f"Async execution failed for {module_name}: {str(e)}")

@powershell_bp.route('/powershell/scripts', methods=['GET'])
def get_available_scripts():
    """Get list of available PowerShell scripts"""
    try:
        scripts = []
        for script_name, script_path in POWERSHELL_SCRIPTS.items():
            full_path = get_script_path(script_name)
            scripts.append({
                'name': script_name,
                'path': script_path,
                'exists': os.path.exists(full_path) if full_path else False,
                'description': get_script_description(script_name)
            })
        
        return jsonify({
            'success': True,
            'data': scripts
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def get_script_description(script_name):
    """Get description for a script"""
    descriptions = {
        'ADInfoGatherer': 'Comprehensive Active Directory information collection for Zero Trust assessment',
        'IdentityAnalyzer': 'Comprehensive identity analysis for human and non-human accounts',
        'PermissionAssessor': 'Comprehensive permission and access control analysis',
        'SecurityAuditor': 'Comprehensive security configuration and policy auditing'
    }
    return descriptions.get(script_name, 'No description available')

@powershell_bp.route('/powershell/execute', methods=['POST'])
def execute_script():
    """Execute a PowerShell script manually"""
    try:
        data = request.json
        
        # Validate required fields
        if 'script_name' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required field: script_name'
            }), 400
        
        script_name = data['script_name']
        parameters = data.get('parameters', {})
        
        # Get script path
        script_path = get_script_path(script_name)
        if not script_path or not os.path.exists(script_path):
            return jsonify({
                'success': False,
                'error': f'Script not found: {script_name}'
            }), 404
        
        # Execute script
        result = execute_powershell_script(script_path, parameters, timeout=1800)  # 30 minutes
        
        if result['success']:
            parsed_results = parse_powershell_results(result['stdout'], result['stderr'])
            return jsonify({
                'success': True,
                'data': parsed_results,
                'execution_info': {
                    'script_name': script_name,
                    'parameters': parameters,
                    'returncode': result['returncode']
                }
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Script execution failed'),
                'stderr': result.get('stderr', ''),
                'timeout': result.get('timeout', False)
            }), 500
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@powershell_bp.route('/powershell/assessments/<int:assessment_id>/run', methods=['POST'])
def run_assessment(assessment_id):
    """Run all modules for a specific assessment"""
    try:
        assessment = Assessment.query.get_or_404(assessment_id)
        
        if assessment.status == 'running':
            return jsonify({
                'success': False,
                'error': 'Assessment is already running'
            }), 400
        
        # Update assessment status
        assessment.status = 'running'
        db.session.commit()
        
        # Get assessment modules
        modules = AssessmentModule.query.filter_by(assessment_id=assessment_id).all()
        
        if not modules:
            return jsonify({
                'success': False,
                'error': 'No modules found for this assessment'
            }), 404
        
        # Prepare common parameters
        data = request.json or {}
        base_parameters = {
            'Domain': assessment.domain,
            'OutputPath': data.get('output_path', f'./Assessment_{assessment_id}'),
            'LogPath': data.get('log_path', f'./Logs_{assessment_id}')
        }
        
        # Add assessment-type specific parameters
        if assessment.assessment_type == 'Comprehensive':
            base_parameters['Detailed'] = True
            base_parameters['IncludeNetworkScan'] = True
            base_parameters['IncludeRegistry'] = True
        elif assessment.assessment_type == 'Quick':
            base_parameters['StaleAccountThreshold'] = 180  # More lenient for quick assessment
        
        # Start modules asynchronously
        started_modules = []
        for module in modules:
            if module.status in ['pending', 'failed']:
                # Start module in background thread
                thread = threading.Thread(
                    target=run_assessment_module_async,
                    args=(assessment_id, module.id, module.module_name, base_parameters)
                )
                thread.daemon = True
                thread.start()
                started_modules.append(module.module_name)
        
        return jsonify({
            'success': True,
            'message': f'Assessment started with {len(started_modules)} modules',
            'data': {
                'assessment_id': assessment_id,
                'started_modules': started_modules,
                'total_modules': len(modules)
            }
        })
        
    except Exception as e:
        # Revert assessment status on error
        try:
            assessment = Assessment.query.get(assessment_id)
            if assessment:
                assessment.status = 'failed'
                db.session.commit()
        except:
            pass
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@powershell_bp.route('/powershell/assessments/<int:assessment_id>/modules/<int:module_id>/run', methods=['POST'])
def run_assessment_module(assessment_id, module_id):
    """Run a specific assessment module"""
    try:
        module = AssessmentModule.query.filter_by(
            id=module_id,
            assessment_id=assessment_id
        ).first_or_404()
        
        if module.status == 'running':
            return jsonify({
                'success': False,
                'error': 'Module is already running'
            }), 400
        
        assessment = Assessment.query.get(assessment_id)
        
        # Prepare parameters
        data = request.json or {}
        parameters = {
            'Domain': assessment.domain,
            'OutputPath': data.get('output_path', f'./Assessment_{assessment_id}'),
            'LogPath': data.get('log_path', f'./Logs_{assessment_id}')
        }
        
        # Add module-specific parameters
        if module.module_name == 'IdentityAnalyzer':
            parameters['StaleAccountThreshold'] = data.get('stale_account_threshold', 90)
        elif module.module_name == 'PermissionAssessor':
            parameters['IncludeShares'] = data.get('include_shares', True)
            parameters['IncludeRegistry'] = data.get('include_registry', False)
        elif module.module_name == 'SecurityAuditor':
            parameters['IncludeNetworkScan'] = data.get('include_network_scan', False)
            parameters['IncludeServiceScan'] = data.get('include_service_scan', True)
        
        # Start module in background thread
        thread = threading.Thread(
            target=run_assessment_module_async,
            args=(assessment_id, module_id, module.module_name, parameters)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'message': f'Module {module.module_name} started',
            'data': {
                'assessment_id': assessment_id,
                'module_id': module_id,
                'module_name': module.module_name
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@powershell_bp.route('/powershell/assessments/<int:assessment_id>/status', methods=['GET'])
def get_assessment_status(assessment_id):
    """Get the current status of an assessment"""
    try:
        assessment = Assessment.query.get_or_404(assessment_id)
        modules = AssessmentModule.query.filter_by(assessment_id=assessment_id).all()
        
        module_status = {}
        overall_status = 'pending'
        
        completed_count = 0
        failed_count = 0
        running_count = 0
        
        for module in modules:
            module_status[module.module_name] = {
                'status': module.status,
                'started_at': module.started_at.isoformat() if module.started_at else None,
                'completed_at': module.completed_at.isoformat() if module.completed_at else None,
                'error_message': module.error_message
            }
            
            if module.status == 'completed':
                completed_count += 1
            elif module.status == 'failed':
                failed_count += 1
            elif module.status == 'running':
                running_count += 1
        
        # Determine overall status
        if completed_count == len(modules):
            overall_status = 'completed'
            assessment.status = 'completed'
            assessment.completed_at = datetime.utcnow()
            db.session.commit()
        elif failed_count > 0 and running_count == 0:
            overall_status = 'failed'
            assessment.status = 'failed'
            db.session.commit()
        elif running_count > 0:
            overall_status = 'running'
        
        return jsonify({
            'success': True,
            'data': {
                'assessment_id': assessment_id,
                'overall_status': overall_status,
                'progress': {
                    'completed': completed_count,
                    'failed': failed_count,
                    'running': running_count,
                    'pending': len(modules) - completed_count - failed_count - running_count,
                    'total': len(modules),
                    'percentage': (completed_count / len(modules) * 100) if len(modules) > 0 else 0
                },
                'modules': module_status
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

