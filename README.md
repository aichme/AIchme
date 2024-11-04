# AIchme
The solution we propose is a web application that attempts to predict potential APTs who
could use a particular CVE for malicious purposes, taking into account the
actions they had carried out in previous attacks, as documented on the MITRE
ATT&CK website.

The user has the option to choose one of the available CVEs that have been
collected and are stored in our database or to enter the description of any CVE
he would like to check.

Using the LLM `meta/llama-3.1-8b-instruct` through NVIDIA NIM, a list of methods
for the selected CVE is extracted from its description.

The extracted methods are compared with the methods previously used by APTs
using similarity search. The methods that each APT has used in the past, have
already been stored as embeddings in a Milvus Vector Store, utilizing the
`basel/ATTACK-BERT` embeddings model from Hugging Face.

The user is getting redirected to the **Results** page, where a summary of the
matches is displayed, along with some useful graphs and the detailed list of the
matches. 


## Architecture
This repo is splitted into 3 different folders:  
1. embeddings
2. scrapper
3. website

The folder `website` contains the proposed system and the folders `embeddings`
and `scrapper` contain the additional scripts we used for data collection and
preprocessing. 

### Web Application
![Diagram of the web app](diagrams/webapp.png)
Once the user visits the web application, he can select either to select a CVE from the
local collection or to insert the description for the CVE of his choice. The
local collection of CVEs is stored in the 'cves_dataset' subfolder. The
extraction of this collection is described in the [following
section](#methods-extraction). Entering the CVE description, the LLM will be
used to extract the methods using the same prompt. 

After the methods extraction, the user will be redirected to the results page. A
similarity search is being calculated for each method, using the vector store
that is created as described in the section [Vector Store
Creation](#vector-store-creation). 

Those matches are filtered using an LLM, comparing each one of them with the
original CVE description and keeping only those matches that are considered as
valid. Finally, the filtered matches are given as input to another LLM that
generates a human friendly and informative summary of the final results. 

The final results that the user has access to are the following:
* The summary, where the potentiality of each APTs threat is being mentioned.
* A histogram that shows the number of matches per APT. 
* A pie chart that displays the number of matches per each method.
* A detailed list of all the possible matches that our system identified.


### Vector Store Creation
Vector store creation is a three step process:
#### Step 1: Scrapping 
[MITRE ATT&CK Groups](https://attack.mitre.org/groups/) website scrapping to
   collect the data about the APTs. For each group, we collect the `Use` field
   from the `Techniques Used` section.

#### Step 2: Data Preprocessing with NeMo Curator
We use Nemo Curator to preprocess the data that were extracted from the scrapping.
In the preprocessing, for each APT:

* We remove the APT name from the APT's `Use` fields.
* We remove any references from the APT's `Use` fields.
* We replace any CVE reference, with the CVE's description.

#### Step 3: Milvus Vector Store
We use the [ATTACK-BERT](https://huggingface.co/basel/ATTACK-BERT) model for the
embedding model and the [Milvus](https://milvus.io/) database for storing the
embeddings.

### Methods Extraction
The CVE method extraction uses llama-3_1-8b-instruct model with a specially
crafted prompt to extract the methods from the CVE's description. We have a
database with the CVE descriptions and used the LLM to extract the methods.

## Installation
### Installing the necessary libraries
```
$ python3 -m venv .venv
$ pip install -r requirements.txt
```

### Acquiring the NVIDIA NIM API KEY
Please follow one of the following options:
* NVIDIA provides a [helpful guide](https://docs.nvidia.com/nim/large-language-models/latest/getting-started.html#generate-an-api-key) for acquiring the required api key. The necessary steps are explained in the subsection named `Generate an API key` of the section `Option 1: From API catalog`.
* There is also a [YouTube video](https://www.youtube.com/watch?v=087spL8hMvM) that demonstrates how to deploy NVIDIA NIM, including the creation of the API key.

### Starting the NVIDIA NIM LLM
``` 
$ export NGC_API_KEY="NVIDIA_NIM_API_KEY_HERE"
$ ./run_llama.sh 
```

> Note: Due to resources limitation (GPU VRAM Size) we used in the shell script
a smaller context window and a higher GPU memory utilization (default:0.9).
Those parameters can be omitted, if there are no resources limits.

#### Case: Authentication required
In the case that an authentication is required, you need to authenticate
yourself using the following commands in a terminal:
```
$ docker login nvcr.io
Username: $oauthtoken
Password: NVIDIA_NIM_API_KEY_HERE
```

For more details about the installation of the NVIDIA NIM model:  
[llama-3_1-8b-instruct](https://build.nvidia.com/meta/llama-3_1-8b-instruct?snippet_tab=Docker)


### NeMo Curator
We faced problems during the installation of the NeMo Curator and we propose the
following steps for successfully installing the tool and using it (based on the
[Source installation](https://github.com/NVIDIA/NeMo-Curator?tab=readme-ov-file#source)):

1. Clone the repository `git clone https://github.com/NVIDIA/NeMo-Curator.git`
2. In the cloned repository, in the `NeMo-Curator/requirements/requirements.txt`
   file replace requirement `fasttext` with `fasttext-wheel` (keep the same version)
3. Install cython `pip install cython`
4. Install the package from the repo:
`pip install --extra-index-url https://pypi.nvidia.com "./NeMo-Curator[all]"`


## Running the Web Application
1. Run the LLM as described in the [Starting the NVIDIA NIM LLM](#starting-the-nvidia-nim-llm).
2. Make sure that you have activated the virtual environment:  
   `source .venv/bin/activate`
3. Start the flask server with the following command:  
   `python3 website/app.py`
4. Now you can access the web application through the browser, visiting the url:  
   http://127.0.0.1:5001
> Note: Please open the config.py and edit the `secret_key` variable with a key of your choice. 

