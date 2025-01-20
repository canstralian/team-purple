import gradio as gr
import pandas as pd
import plotly.express as px
from transformers import pipeline
import matplotlib.pyplot as plt

cve_chart = plt.figure()
# Plot data (example)
cve_chart.plot(generate_cve_chart)
plt.show()


# Sample data for CVEs
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

# Convert the data to a DataFrame
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
        cve_chart.plot(generate_cve_chart)

    # Sentiment Analysis
    with gr.Row():
        description_input = gr.Textbox(label='CVE Description')
        sentiment_output = gr.JSON(label='Sentiment Analysis')
        analyze_btn = gr.Button('Analyze Sentiment')

    # Event listener for sentiment analysis
    analyze_btn.click(fn=analyze_sentiment, inputs=description_input, outputs=sentiment_output)

# Launch the app
demo.launch(share=True)
