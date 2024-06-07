import os

def find_files(directory):
    html_files = []
    python_files = []
    for root, dirs, filenames in os.walk(directory):
        for filename in filenames:
            if filename.endswith('.html') and 'templates' in root:
                html_files.append(os.path.join(root, filename))
            elif filename in ['appes.py']:
                python_files.append(os.path.join(root, filename))
    return html_files, python_files

def save_contents(html_files, python_files, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        for file_path in html_files:
            with open(file_path, 'r', encoding='utf-8') as file:
                contents = file.read()
                f.write(f"Файл: {file_path}\n\n")
                f.write(contents)
                f.write("\n\n")
        for file_path in python_files:
            with open(file_path, 'r', encoding='utf-8') as file:
                contents = file.read()
                f.write(f"Файл: {file_path}\n\n")
                f.write("```python\n")
                f.write(contents)
                f.write("\n```\n\n")

if __name__ == "__main__":
    directory = os.getcwd()  # Текущая директория
    output_file = 'output.txt'  # Имя выходного файла

    html_files, python_files = find_files(directory)
    save_contents(html_files, python_files, output_file)
    print(f"Содержимое файлов сохранено в {output_file}")