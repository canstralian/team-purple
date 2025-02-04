import plotly.express as px
import gradio as gr
import pandas as pd
from textblob import TextBlob  # Example sentiment analysis library

# Example DataFrame definitions (replace with actual data loading)
cve_df = pd.DataFrame({
    'Severity': ['High', 'Medium', 'Low'],
    'CVE ID': ['CVE-1234', 'CVE-5678', 'CVE-9101']
})
deepseek_prover_v1 = pd.DataFrame()
cybersecurity_kg = pd.DataFrame()
codesearchnet_pep8 = pd.DataFrame()
code_text_python = pd.DataFrame()

# Function to generate a bar chart of CVEs by severity
def generate_cve_chart(dataframe):
    fig = px.bar(dataframe, x='Severity', y='CVE ID', color='Severity', title='CVEs by Severity')
    return fig

# Function to filter CVEs based on severity
def filter_cves(severity):
    return cve_df[cve_df['Severity'] == severity]

# Function to analyze sentiment of a description
def analyze_sentiment(description):
    analysis = TextBlob(description)
    sentiment = 'positive' if analysis.sentiment.polarity > 0 else 'negative' if analysis.sentiment.polarity < 0 else 'neutral'
    return {"sentiment": sentiment, "confidence": abs(analysis.sentiment.polarity)}

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
        cve_chart.value = generate_cve_chart(cve_df)  # Directly assign the figure to the Plot component

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