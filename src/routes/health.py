from flask_restx import Namespace, Resource
ns = Namespace('health', description='Health')
@ns.route('/healthz')
class Health(Resource):
    def get(self): return {'ok': True}
