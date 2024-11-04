import json
import argparse
from langchain_milvus import Milvus
from langchain_core.documents import Document
from langchain_huggingface import HuggingFaceEmbeddings

def load_jsonl(file_path):
    data = []
    with open(file_path, 'r') as f:
        for line in f:
            data.append(json.loads(line))
    return data

def main(args):
    model_name = 'basel/ATTACK-BERT'
    device = 'cuda' if args.use_gpu else 'cpu'
    model_kwargs = {'device': device, 'trust_remote_code': True}
    encode_kwargs = {'normalize_embeddings': True}
    hf = HuggingFaceEmbeddings(
        model_name=model_name,
        model_kwargs=model_kwargs,
        encode_kwargs=encode_kwargs
    )

    vector_store = Milvus(
        embedding_function=hf,
        connection_args={"uri": args.store_uri},
        collection_name="usages",
    )

    jsonl_data = load_jsonl(args.data_file)

    texts = [item['text'] for item in jsonl_data]
    metadata_list = [{k: v for k, v in item.items() if k != 'text'} for item in jsonl_data]
    documents = [Document(page_content=text, metadata=metadata) for text,metadata in zip(texts, metadata_list)]
    ids = [metadata['id'] for metadata in metadata_list]
    vector_store.add_documents(documents=documents, ids=ids)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create the vector store from the given data.')
    parser.add_argument('-s', '--store_uri', help='Where to store the vector store (Milvus) database', required=True)
    parser.add_argument('-f', '--data_file', help='Path to the file that contains the data in jsonl format', required=True)
    parser.add_argument('--use_gpu', help='Load the model in the GPU', action='store_true')
    main(parser.parse_args())