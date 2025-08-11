import os
from flask_restx import Namespace, Resource
from flask import send_file
ns = Namespace('report', description='Reports')
@ns.route('/report/latest')
class Latest(Resource):
    def get(self):
        p = os.path.join('out','executive_summary.pdf')
        if not os.path.exists(p): return {'error':'no report yet'}, 404
        return send_file(p, as_attachment=True, download_name='executive_summary.pdf')
