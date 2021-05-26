import os
import glob
import controller
import json
from flask import Flask, render_template, request, jsonify, url_for
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'py'}

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload')
def upload():
    return render_template('upload.html')
	
@app.route('/uploader', methods = ['GET', 'POST'])
def uploader():
    if request.method == 'POST':
        # delete old output file in static
        files = glob.glob('./static/*.py.png')
        for f in files:
            print('tes : ',f)
            os.remove(f)

        # get python file
        f = request.files['file']
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], f.filename))

        # analyze code
        vulnerabilities, exec_time, count_node = controller.analyze_code(f.filename)

        # remove uploded file
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], f.filename))

        # get image output from visualize path
        image = os.path.join(f.filename + '.png')

        print(image)

        return render_template('analyze.html', user_image = image, vulnerable = convertToJSON(vulnerabilities), exec_time = exec_time, count_node = count_node, file_name = f.filename)

def convertToJSON(vulnerabilities):
    result = []
    for vulnerable in vulnerabilities:
        temp = {}
        temp['node'] = {
            'line': vulnerable.node.ast_node.lineno,
            'code': vulnerable.node.source(),
        }
        temp['vulnerable_type'] = vulnerable.vulnerable_type
        result.append(temp)
        
    return result

@app.route('/')
def hello_world():
   return render_template('upload.html')

@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r
		
if __name__ == '__main__':
   app.run(debug = True)