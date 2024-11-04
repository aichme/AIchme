from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import json 
import models
import embeddings
from pprint import pprint
import config
import parsers

class WebAppAPI:
    def __init__(self):
        self.app: Flask = Flask(__name__)
        self.app.secret_key = config.secret_key
        self.embeddings_model = embeddings.load_embeddings_model()
        self.vector_store = embeddings.load_vector_store(embeddings_model=self.embeddings_model)
        self.CVES = parsers.load_cves_dataset()

    def run_server(self) -> None:
        self.app.route("/", methods=["GET", "POST"])(self.index)
        self.app.route("/search", methods=["GET"])(self.search)
        self.app.route("/submit", methods=["POST"])(self.submit)
        self.app.route("/results")(self.results)
        self.app.route("/generate_results", methods=["POST"])(self.get_llm_response)
        self.app.run(host='127.0.0.1', port=5001)

    def index(self):
        """
        Returns the HTML for the index page.
        """
        if request.method == 'GET':
            return render_template('index.html', names=[])

    def search(self):
        """
        Search into the filenames' dataset, after processing GET request.

        Expects:
            - query key in the request args

        Returns:
            Dictionary with keys:
            - 'options': List of the search results for the given query.
        """
        query = request.args.get('query', '')
        
        # Simulate filtering from a large dataset
        filtered_options = [item for item in self.CVES if query in item]

        # Limit the results to a smaller set (e.g., first 100 results)
        filtered_options = filtered_options[:20]
        return jsonify({'options': filtered_options})


    def submit(self):
        """
        Submit a request for threat prediction, after processing POST request.

        Expects:
            - selectedOption key in the request body
            - cve key in the request body
            - description key in the request body

        Returns:
            - 200 on success, redirecting to results.html page.
            - 400 on validation error, with a message.
            - 500 on internal server error
        """
        data = request.json
        
        selected_option = data.get('selectedOption')
        cve = data.get('cve')
        description = data.get('description')

        print(f"Selected Option: {selected_option}")
        print(f"CVE: {cve}")
        print(f"description: {description}")

        validation_error = None 

        try: 
            if selected_option == 'database':
                if cve is not None and cve in self.CVES:
                    with open(f"{config.CVE_FOLDER_PATH}/{cve}.json", 'r') as f:
                        cve_content = json.load(f)
                    cve = cve.split('.')[0]
                    description = cve_content['description']
                    methods_list = cve_content['methods']
                else:
                    validation_error = 'You should select a valid CVE from the list.'
                    return jsonify({'status': False, 'message': validation_error}), 400
            elif selected_option == 'text':
                if description is not None:
                    methods_list = models.extract_methods_from_cve(description=description)
                    if not cve:
                        cve = 'Unknown'
                else:
                    validation_error = 'Description can\'t be None: Nothing to extract from it.'
                    return jsonify({'status': False, 'message': validation_error}), 400
            else:
                validation_error = 'Something went wrong on input validation.'
                return jsonify({'status': False, 'message': validation_error}), 400

        except Exception as e:
            validation_error = 'Something went wrong on input validation.'
            print(e)
            return jsonify({'status': False, 'message': validation_error}), 500

        methods_json = json.dumps(methods_list)
        session['cve'] = cve
        session['description'] = description
        session['methods'] = methods_json
        return redirect(url_for('results'))

    def results(self):
        """
        Render template for the results page.
        """
        cve = session.get('cve')
        description = session.get('description')
        methods = json.loads(session.get('methods'))
        return render_template('results.html', cve=cve, description=description, methods=methods)


    def get_llm_response(self):
        """
        Calculate the predictions/results, after processing GET request.

        Expects:
            - methods key in the request body
            - description key in the request body

        Returns:
            Dictionary with keys:
            - 'total_matches': List of the total matches calculated.
            - 'histogram': Dict that contains the information for plotting the histogram
            - 'matches_counter': Dict that contains the information for plotting the pie chart
            - 'summary': String with the summary 
            - 'error': Contains information about the error, when an error occurs. 
        """
        try:
            data = request.get_json()
            methods = data.get('methods', [])
            description = data.get('description', None)

            result_dict = embeddings.compare_with_vector_store(self.vector_store, methods, description, threshold=1)
            return jsonify(result_dict)
        except Exception as e:
            pprint({"total_matches": [], "histogram": {}, "matches_counter": {}, "summary": "", "error": str(e)})
            return jsonify({"total_matches": [], "histogram": {}, "matches_counter": {}, "summary": "", "error": str(e)})


if __name__ == '__main__':
    webapp_api: WebAppAPI = WebAppAPI()
    webapp_api.run_server()
