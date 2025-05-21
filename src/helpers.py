import os

def write_pdf_to_directory(response, filename, file_directory):
  
    isExist = os.path.exists(file_directory + "//" + filename)
    if isExist == False:
        with open(file_directory + "//" + filename, 'wb') as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)
        #print(f"Downloaded PDF: {filename}")
    else:
        error = "error"
    return