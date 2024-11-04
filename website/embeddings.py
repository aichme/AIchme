from langchain_huggingface import HuggingFaceEmbeddings
from langchain_milvus import Milvus
from pprint import pprint 
import parsers
import models 
import markdown
import config

def load_embeddings_model():
    """ 
    Loads the 'basel/ATTACK-BERT' embeddings model from Hugging Face.
    """
    embeddings_model = HuggingFaceEmbeddings(
        model_name="basel/ATTACK-BERT",
        model_kwargs={'device': 'cpu', 'trust_remote_code': True},
        encode_kwargs={'normalize_embeddings': True}
    )
    return embeddings_model

def load_vector_store(embeddings_model):
    """ 
    Loads the 'Milvus' vector store that is already created and stored in the local storage.
    """
    vector_store = Milvus(
        embedding_function=embeddings_model,
        connection_args={"uri": config.vector_store_path},
        collection_name='usages',
        search_params={"metric_type": "L2"}
    )
    return vector_store




def find_similarities(vector_store, texts:list, threshold:float=1, k:int=25):
    """
    Find the strong matches between the input texts and the vector store.

    Expects:
        - vector_store: The Milvus vector store that contains the APT methods from the past.
        - texts: List of methods. We compare each list item with the vector store for receiving the best matches. 

    Optional:
        - threshold: The matches should have a score lower than the threshold. (Default: 1, score range: [0, 2])
        - k: The maximum number of matches for a text from the list. (Default: 25)

    Returns:
        - total_strong_matches: List of dictionaries, where each dictionary is a match that contains information about:
        the APT, a unique ID, a score, the usage as it is stored in the vector store and the current method. 
    """
    total_strong_matches = []
    matches_ids = []

    print('Starting similarity search...')
    for i,text in enumerate(texts):
        print(50*'~')
        print(f'Method: #{i}')
        print(text)
        print('\n')
        results = vector_store.similarity_search_with_score(
            text,
            k=k,
        )
    
        threat_actors = []
        scores = []
        strong_matches = []
        
        for document, score in results:
            threat_actors.append(document.metadata['filename'])
            scores.append(score)
            if score < threshold:
                name = document.metadata['filename']
                use_id = document.metadata['id']
                text = document.page_content
                if use_id in matches_ids:
                    continue
                else:
                    matches_ids.append(use_id)
                    strong_matches.append(
                        {'APT': name,
                        'Score': round(score,3),
                        'ID': use_id,
                        'Usage': text,
                        'Method': i + 1
                        }
                    )

        total_strong_matches.extend(strong_matches)

    print('# of total strong matches: ', len(total_strong_matches))
    return total_strong_matches


def filter_matches(matches:list, description:str, batch_size=15) -> list:
    """
    Filter the matches with the help of an LLM.

    Expects:
        - matches: List of matches, where each match is a dictionary.
        - description: The official description of the current CVE.

    Optional:
        - batch_size: The number of batches that the LLM will process in each batch. (Default: 15)

    Returns:
        - final_matches: List of the filtered matches.
    """
    def batch_data(matches):
        """Yield successive batches from 'matches' list."""
        for i in range(0, len(matches), batch_size):
            yield matches[i:i + batch_size]

    llm = models.init_llm(temperature=0)
    match_texts = [{'usage':match['Usage'], 'id': match['ID']} for match in matches]

    print('Filtering extracted matches...')
    final_ids = []
    for i,batch in enumerate(batch_data(match_texts)):
        print(f'Processing batch #{i}')
        filtering_prompt = models.create_prompt_for_filtering(matches=batch, description=description)
        response = llm.chat(filtering_prompt)
        response = response.message.content
        final_ids.extend(parsers.parse_list_response(response))
    
    final_matches = []
    for match in matches: 
        if match['ID'] in final_ids:
            final_matches.append(match)
    print('Num of final matches: ', len(final_matches))
    return final_matches

def extract_summary(methods:list, matches_per_method:dict, description:str):
    """
    Extract summary out of the matches with the help of an LLM.

    Expects:
        - methods: List of methods
        - matches_per_method: A dictionary that maps the matches to the method they belong.
        - description: The official CVE description

    Returns:
        - The LLM response, transformed in markdown.
    """
    llm = models.init_llm(temperature=0.7)
    summary_prompt = models.create_prompt_for_summarization(methods=methods, matches_per_method=matches_per_method, description=description)
    response = llm.chat(summary_prompt)
    return markdown.markdown(response.message.content)

def calculate_k(n: int):
    """
    Helpful mathematical function that calculates the k (the maximum number of matches per method),
    based on the number of the methods for this CVE.
    We try to reduce the value of the k as the value of the n raises and vice versa. 
    """
    if n <= 2:
        k = 30
    elif 2 < n < 6:
        k = 5 * (8 - n)
    elif 6 <= n <= 8:
        k = 10
    else:
        k = 5    
    return k

def compare_with_vector_store(vector_store, methods:list, description: str, threshold: float = 0.75):
    """
    Receive the vector store, the list of methods, the CVE description and the score threshold value and:
    1. Find the matches between the methods and the vector store entries.
    2. Filter the matches with the help of an LLM. 
    3. Extract the summary of the final results as a human-readable text. 
    """
    k = calculate_k(len(methods))
    strong_matches = find_similarities(vector_store, methods, threshold=threshold, k=k)
    if len(strong_matches) > 0:
        filtered_matches = filter_matches(strong_matches, description, batch_size=15)
        actors_count = parsers.calculate_possible_actors(filtered_matches)
        final_matches_count, matches_per_method = parsers.count_matches_per_method(filtered_matches)
        summary = extract_summary(methods, matches_per_method, description)
        pprint({"total_matches": filtered_matches, "histogram": actors_count, "matches_counter": final_matches_count, "summary": summary})
        return {"total_matches": filtered_matches, "histogram": actors_count, "matches_counter": final_matches_count, "summary": summary, "error": ""}
    else:
        return {"total_matches": [], "histogram": {}, "matches_counter": {}, "summary": "", "error": ""}