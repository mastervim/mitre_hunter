import streamlit as st
import pandas as pd
import time
import threading
from streamlit.runtime.scriptrunner import add_script_run_ctx
try:
    from .loader import MitreLoader
    from .query import MitreQuery
    from .loader import MitreLoader
    from .query import MitreQuery
    from .converter import SigmaConverter
    from . import __version__
except ImportError:
    from loader import MitreLoader
    from query import MitreQuery
    from converter import SigmaConverter
    # Fallback if package import fails (e.g. running script directly)
    __version__ = "1.3.0"
import json
import io
import yaml

st.set_page_config(page_title=f"MitreHunter v{__version__} | Enterprise Threat Hunting", page_icon="🛡️", layout="wide")

@st.cache_data
def load_data():
    loader = MitreLoader()
    return loader.parse_data()

@st.cache_data
def load_sigma_rules():
    loader = MitreLoader()
    # This now uses the JSON cache internally, so it's fast
    return loader.parse_sigma_rules()

def main():
    st.title(f"🛡️ MitreHunter v{__version__}: Threat Hunting Tool")
    st.markdown("Query MITRE ATT&CK TTPs based on Data Sources for effective threat hunting.")

    try:
        # Enterprise-grade loading status
        if 'data_loaded' not in st.session_state:
            st.session_state.data_loaded = False

        with st.status("Initializing MitreHunter...", expanded=not st.session_state.data_loaded) as status:
            
            st.write("Loading MITRE ATT&CK Data...")
            df = load_data()
            
            st.write("Loading Sigma Rules (Cached)...")
            sigma_rules = load_sigma_rules()
            
            st.write("Building Query Engine...")
            query = MitreQuery(df, sigma_rules)
            
            st.write("Initializing Sigma Converter...")
            converter = SigmaConverter()
            
            st.session_state.data_loaded = True
            status.update(label="System Ready", state="complete", expanded=False)
        
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return

    st.sidebar.header("Filters")

    # Filter by Data Source
    all_datasources = query.get_all_datasources()
    selected_datasource = st.sidebar.selectbox("Select Data Source", ["All"] + all_datasources)

    # Filter by Tactic
    all_tactics = query.get_all_tactics()
    selected_tactic = st.sidebar.selectbox("Select Tactic", ["All"] + all_tactics)

    # Filter by Threat Actor
    all_actors = query.get_all_threat_actors()
    selected_actor = st.sidebar.selectbox("Select Threat Actor", ["All"] + all_actors)

    # Search
    search_term = st.sidebar.text_input("Search by Keyword")
    
    # Sigma Filter
    show_sigma_only = st.sidebar.checkbox("Show only techniques with Detections (Sigma/Splunk/CS)")

    # Apply filters
    filtered_df = df.copy()

    if selected_datasource != "All":
        # Re-implement filter logic here or use query object methods if they returned indices/df
        # Using query object methods is cleaner but they return new DFs.
        # Let's use the query object methods for consistency.
        filtered_df = query.filter_by_datasource(selected_datasource)

    if selected_tactic != "All":
         # We need to chain filters. The query object methods start from full DF.
         # So we should probably filter the 'filtered_df' manually or refactor query.py to accept a DF.
         # For simplicity, let's just filter 'filtered_df' here using the logic from query.py
         tactic = selected_tactic.lower().replace(" ", "-")
         mask = filtered_df['tactics'].apply(lambda x: any(tactic in t.lower().replace(" ", "-") for t in x) if isinstance(x, list) else False)
         filtered_df = filtered_df[mask]

    if selected_actor != "All":
        actor = selected_actor.lower()
        mask = filtered_df['threat_actors'].apply(lambda x: any(actor in a.lower() for a in x) if isinstance(x, list) else False)
        filtered_df = filtered_df[mask]

    if search_term:
        keyword = search_term.lower()
        mask = filtered_df.apply(lambda x: keyword in x['name'].lower() or keyword in x['description'].lower(), axis=1)
        filtered_df = filtered_df[mask]
        
    if show_sigma_only:
        sigma_ids = set(query.sigma_rules.keys())
        # Filter for IDs that are in the sigma_rules dict
        mask = filtered_df['external_id'].isin(sigma_ids)
        filtered_df = filtered_df[mask]

    # Display results
    st.subheader(f"Found {len(filtered_df)} Techniques")

    if not filtered_df.empty:
        # Add Sigma count column for display
        # We use a lambda to look up the count from the query object
        filtered_df['sigma_count'] = filtered_df['external_id'].apply(lambda x: len(query.get_sigma_rules_for_technique(x)))
        
        # Display as a dataframe with specific columns
        display_df = filtered_df[['external_id', 'name', 'sigma_count', 'tactics', 'data_sources', 'platforms', 'threat_actors']]
        display_df = display_df.rename(columns={"sigma_count": "Detections"})
        
        # Interactive Table
        st.info("👆 Click on a row to view details")
        event = st.dataframe(
            display_df, 
            width=None, 
            use_container_width=True,
            on_select="rerun",
            selection_mode="multi-row"
        )
        
        # Export Logic
        st.sidebar.markdown("---")
        st.sidebar.subheader("Export Artifacts")
        
        selected_indices = event.selection.rows
        
        if not selected_indices:
            st.sidebar.info("Select techniques in the table to enable export.")
        else:
            st.sidebar.write(f"**{len(selected_indices)} techniques selected**")
            
            if st.sidebar.button("⚡ Generate Export Artifacts"):
                with st.status("Generating Artifacts...", expanded=True) as status:
                    export_df_source = filtered_df.iloc[selected_indices]
                    all_export_data = []
                    progress_bar = status.progress(0)
                    total_rows = len(export_df_source)
                    
                    for idx, (index, row) in enumerate(export_df_source.iterrows()):
                        tech_id = row['external_id']
                        tech_name = row['name']
                        
                        rules = query.get_sigma_rules_for_technique(tech_id)
                        if rules:
                            for rule in rules:
                                try:
                                    with open(rule['path'], 'r', encoding='utf-8') as f:
                                        raw_yaml = f.read()
                                except:
                                    raw_yaml = ""
                                
                                queries = converter.convert_to_all(raw_yaml)
                                
                                all_export_data.append({
                                    "TechniqueID": tech_id,
                                    "TechniqueName": tech_name,
                                    "RuleTitle": rule['title'],
                                    "RuleLevel": rule['level'],
                                    "SplunkQuery": queries['splunk'],
                                    "CrowdStrikeQuery": queries['crowdstrike']
                                })
                        
                        progress_bar.progress((idx + 1) / total_rows)
                    
                    # Prepare downloads
                    export_df = pd.DataFrame(all_export_data)
                    
                    # CSV
                    csv_data = export_df.to_csv(index=False).encode('utf-8')
                    
                    # JSON
                    json_str = json.dumps(all_export_data, indent=2)
                    
                    # YAML
                    yaml_str = yaml.dump(all_export_data, sort_keys=False)
                    
                    status.update(label="Artifacts Ready!", state="complete", expanded=False)
                    
                    st.sidebar.markdown("### Download")
                    st.sidebar.download_button("📥 Download CSV", csv_data, "mitre_hunter_export.csv", "text/csv")
                    st.sidebar.download_button("📥 Download JSON", json_str, "mitre_hunter_export.json", "application/json")
                    st.sidebar.download_button("📥 Download YAML", yaml_str, "mitre_hunter_export.yaml", "application/x-yaml")

        # Detailed view selection logic
        selected_id = None
        
        if len(selected_indices) > 0:
            st.markdown("---")
            
            # Get selected rows
            selected_rows = display_df.iloc[selected_indices]
            options = selected_rows['external_id'].tolist()
            
            # Dropdown
            selected_id = st.selectbox("Select Technique to View Details", options=options)
        
        if selected_id:
            st.subheader(f"Technique Details: {selected_id}")
            details = query.get_technique_details(selected_id)
            if details:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**ID:** {details['external_id']}")
                    st.markdown(f"**Name:** {details['name']}")
                    st.markdown(f"**Tactics:** {', '.join(details['tactics'])}")
                    st.markdown(f"**Threat Actors:** {', '.join(details.get('threat_actors', []))}")
                with col2:
                    st.markdown(f"**Platforms:** {', '.join(details['platforms'])}")
                    st.markdown(f"**Data Sources:** {details['data_sources']}")
                    st.markdown(f"[Link to MITRE ATT&CK]({details['url']})")
                
                st.markdown("### Description")
                st.markdown(details['description'])
                
                # Sigma Rules Section
                sigma_rules = query.get_sigma_rules_for_technique(selected_id)
                if sigma_rules:
                    st.markdown(f"### Detection Queries ({len(sigma_rules)})")
                    
                    # Prepare export data
                    export_data = []
                    
                    for rule in sigma_rules:
                        with st.expander(f"{rule['title']} ({rule['level']})"):
                            st.markdown(f"**Description:** {rule['description']}")
                            
                            # Read raw YAML
                            try:
                                with open(rule['path'], 'r', encoding='utf-8') as f:
                                    raw_yaml = f.read()
                            except Exception:
                                raw_yaml = "Error reading rule file."
                            
                            # Convert on-the-fly
                            queries = converter.convert_to_all(raw_yaml)
                            
                            # Add to export list
                            export_data.append({
                                "title": rule['title'],
                                "id": rule['id'],
                                "splunk": queries['splunk'],
                                "crowdstrike": queries['crowdstrike']
                            })
                            
                            # Display Tabs
                            tab1, tab2, tab3 = st.tabs(["Sigma Rule", "Splunk", "CrowdStrike"])
                            
                            with tab1:
                                st.code(raw_yaml, language='yaml')
                            with tab2:
                                st.code(queries['splunk'], language='splunk')
                            with tab3:
                                st.code(queries['crowdstrike'], language='text')
                    

                    
                else:
                    st.info("No Sigma rules found for this technique.")

if __name__ == "__main__":
    main()
