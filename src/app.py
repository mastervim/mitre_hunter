import streamlit as st
import pandas as pd
from loader import MitreLoader
from query import MitreQuery

st.set_page_config(page_title="MitreHunter", page_icon="🛡️", layout="wide")

@st.cache_data
def load_data():
    loader = MitreLoader()
    return loader.parse_data()

def main():
    st.title("🛡️ MitreHunter: Threat Hunting Tool")
    st.markdown("Query MITRE ATT&CK TTPs based on Data Sources for effective threat hunting.")

    try:
        with st.spinner("Loading MITRE ATT&CK Data..."):
            df = load_data()
        query = MitreQuery()
        # Force reload of df in query object to ensure it uses cached data properly if needed, 
        # though MitreQuery loads it internally. 
        # Optimization: Pass df to MitreQuery if we refactor, but for now it's fine.
        
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

    # Display results
    st.subheader(f"Found {len(filtered_df)} Techniques")

    if not filtered_df.empty:
        # Display as a dataframe with specific columns
        display_df = filtered_df[['external_id', 'name', 'tactics', 'data_sources', 'platforms', 'threat_actors']]
        st.dataframe(display_df, width='stretch')

        # Detailed view
        st.markdown("---")
        st.subheader("Technique Details")
        selected_id = st.selectbox("Select Technique ID to view details", filtered_df['external_id'].tolist())
        
        if selected_id:
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

if __name__ == "__main__":
    main()
