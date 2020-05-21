from flask import Flask, jsonify, request, session, make_response, render_template
from functools import wraps
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'API_TOKEN'

def check_for_token(func):
	@wraps(func)

	def wrapped(*args, **kwargs):
		token = request.args.get('token')

		if not token:
			return jsonify({'message': 'Missing token'}), 403

		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])

		except:
			return render_template('login.html')

		return func(*args, **kwargs)

	return wrapped


@app.route('/')
def index():
	if not session.get('logged_in'):
		return render_template('login.html')

	else:
		return 'Currently logged in'


@app.route('/public')
def public():
	return 'Public to all to see'


@app.route('/auth')
@check_for_token
	
def authorised():
	temp = None

	if request.method == 'POST':
		if request.form['ledBtn'] == 'led1':
			temp = 'ON'

		elif request['ledBtn'] == 'led2':
			temp = 'OFF'

	elif request.method == 'GET':
		return render_template('home.html', temp=temp)


@app.route('/login', methods=['POST'])
def login():
	if request.form['username'] == 'admin' and request.form['password'] == 'password':
		session['logged_in'] = True
		token = jwt.encode({
			'user': request.form['username'],
			'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
		},
		
		app.config['SECRET_KEY'])
		return jsonify({'token': token.decode('utf-8')})

	elif request.form['username'] == 'martin' and request.form['password'] == '1234':
		session['logged_in'] = True
		token = jwt.encode({
			'user': request.form['username'],
			'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
		},
		
		app.config['SECRET_KEY'])
		return jsonify({'token': token.decode('utf-8')})

	else:
		return make_response('Unable to vertify', 403, {'WWW-Authenticate': 'Basic realm="User Visible Realm"'})



if __name__ == '__main__':
	app.run(debug=True)