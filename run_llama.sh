export LOCAL_NIM_CACHE=~/.cache/nim
mkdir -p "$LOCAL_NIM_CACHE"
docker run -it --rm \
    --gpus all \
    -e NGC_API_KEY \
    -v "$LOCAL_NIM_CACHE:/opt/nim/.cache" \
    -u $(id -u) \
    -p 8001:8000 \
    nvcr.io/nim/meta/llama-3.1-8b-instruct:1.1.2 \
    python3 -m vllm_nvext.entrypoints.openai.api_server --max-model-len 16000 --gpu-memory-utilization 0.95 \
