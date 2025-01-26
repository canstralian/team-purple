import gradio as gr
import pandas as pd
import plotly.express as px
from transformers import pipeline
from datasets import load_dataset

# Load the additional datasets
deepseek_prover_v1 = load_dataset('deepseek-ai/DeepSeek-Prover-V1', split='train')
cybersecurity_kg = load_dataset('CyberPeace-Institute/Cybersecurity-Knowledge-Graph', split='train')
codesearchnet_pep8 = load_dataset('kejian/codesearchnet-python-pep8-v1', split='train')
code_text_python = load_dataset('semeru/code-text-python', split='train')

# Sample CVE data (for visualization)
cve_data = {
    'CVE ID': ['CVE-2023-0001', 'CVE-2023-0002', 'CVE-2023-0003', 'CVE-2023-0004', 'CVE-2023-0005'],
    'Severity': ['High', 'Medium', 'Low', 'High', 'Medium'],
    'Description': [
        'A critical vulnerability in the web application framework.',
        'A medium-severity vulnerability in the database management system.',
        'A low-severity vulnerability in the network firewall.',
        'A critical vulnerability in the operating system kernel.',
        'A medium-severity vulnerability in the web server.'
    ],
    'Published Date': ['2023-01-01', '2023-01-02', '2023-01-03', '2023-01-04', '2023-01-05']
}

# Convert CVE data to a DataFrame
cve_df = pd.DataFrame(cve_data)

# Function to filter CVEs by severity
def filter_cves(severity):
    filtered_df = cve_df[cve_df['Severity'] == severity]
    return filtered_df

# Function to generate a bar chart of CVEs by severity
def generate_cve_chart():
    fig = px.bar(cve_df, x='Severity', y='CVE ID', color='Severity', title='CVEs by Severity')
    return fig

# Function to analyze the sentiment of a CVE description
def analyze_sentiment(description):
    sentiment_pipeline = pipeline('sentiment-analysis')
    result = sentiment_pipeline(description)
    return result

# Create the Gradio app
with gr.Blocks() as demo:
    # Title and description
    gr.Markdown("# Purple Teaming Cyber Security Dashboard")
    gr.Markdown("This dashboard provides threat intelligence and CVEs for purple teaming.")

    # CVE Filter
    with gr.Row():
        severity_filter = gr.Dropdown(choices=['High', 'Medium', 'Low'], label='Filter by Severity')
        cve_table = gr.Dataframe(label='CVEs', value=cve_df)

    # Event listener for severity filter
    severity_filter.change(fn=filter_cves, inputs=severity_filter, outputs=cve_table)

    # CVE Chart
    with gr.Row():
        cve_chart = gr.Plot(label='CVEs by Severity')
        cve_chart.update(generate_cve_chart())

    # Sentiment Analysis
    with gr.Row():
        description_input = gr.Textbox(label='CVE Description')
        sentiment_output = gr.JSON(label='Sentiment Analysis')
        analyze_btn = gr.Button('Analyze Sentiment')

    # Event listener for sentiment analysis
    analyze_btn.click(fn=analyze_sentiment, inputs=description_input, outputs=sentiment_output)

    # Display additional datasets in the dashboard
    with gr.Tab("Datasets Overview"):
        gr.Markdown("## Overview of Additional Datasets")
        
        # Display datasets as dataframes
        with gr.Row():
            gr.Dataframe(label="DeepSeek-Prover-V1", value=deepseek_prover_v1)
            gr.Dataframe(label="Cybersecurity Knowledge Graph", value=cybersecurity_kg)
            gr.Dataframe(label="Code SearchNet Python PEP8", value=codesearchnet_pep8)
            gr.Dataframe(label="Code Text Python", value=code_text_python)

# Launch the app
demo.launch(share=True)