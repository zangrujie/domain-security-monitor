def process_in_chunks(data, max_chunk_size, process_function):
    """
    Splits data into chunks, processes each chunk using the provided function, and combines the results.

    Args:
        data (list): The data to be processed.
        max_chunk_size (int): Maximum size of each chunk.
        process_function (function): Function to process each chunk.

    Returns:
        list: Combined results from processing all chunks.
    """
    chunks = []
    current_chunk = []
    current_size = 0

    # Split data into chunks
    for item in data:
        item_size = len(str(item))  # Calculate size of the item
        if current_size + item_size > max_chunk_size:
            chunks.append(current_chunk)
            current_chunk = []
            current_size = 0
        current_chunk.append(item)
        current_size += item_size

    if current_chunk:
        chunks.append(current_chunk)

    # Process each chunk and combine results
    results = []
    for chunk in chunks:
        result = process_function(chunk)
        results.extend(result)

    return results