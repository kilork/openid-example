if [ -e .env ]; then
    source .env
fi

cargo run --example custom_claims