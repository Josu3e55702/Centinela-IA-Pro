import streamlit as st
import pandas as pd
import joblib
import time
import plotly.express as px
import psutil
import os
import hashlib
import requests
import base64
from fpdf import FPDF

# --- CONFIGURACIÓN DE PÁGINA TOTAL (EDGE-TO-EDGE) ---
st.set_page_config(page_title="Centinela IA Hub Pro", page_icon="🛡️", layout="wide")

# CSS Avanzado para Interfaz Pro de Alto Impacto
st.markdown("""
    <style>
    /* Fondo y Contenedores */
    .stApp { background: linear-gradient(135deg, #0d1117 0%, #000000 100%); }
    .block-container { padding: 1.5rem 2rem !important; }
    
    /* Tarjetas de Cristal */
    .stMetric, div[data-testid="stMetric"] { 
        background-color: rgba(33, 38, 45, 0.4) !important; 
        border: 1px solid #30363d !important; 
        padding: 20px !important; 
        border-radius: 15px !important;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    }
    
    /* Botones de Acción */
    .stButton>button { 
        width: 100%; border-radius: 10px; height: 3.5em; 
        background: linear-gradient(90deg, #1f6feb 0%, #238636 100%);
        color: white; font-weight: bold; border: none; transition: 0.3s;
    }
    .stButton>button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(35, 134, 54, 0.4); }
    
    /* Títulos y Texto */
    h1, h2, h3 { color: #f0f6fc; font-family: 'Inter', sans-serif; font-weight: 800; }
    .status-box { padding: 10px; border-radius: 8px; font-weight: bold; margin: 10px 0; }
    </style>
    """, unsafe_allow_html=True)

# --- LÓGICA DE DATOS Y PDF ---
def generar_pdf(df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="CENTINELA IA - REPORTE TÉCNICO", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=10)
    pdf.cell(40, 10, "Hora", 1); pdf.cell(60, 10, "Resultado", 1); pdf.cell(40, 10, "Red (KB)", 1); pdf.cell(40, 10, "CPU (%)", 1, 1)
    for _, row in df.tail(15).iterrows():
        pdf.cell(40, 10, str(row['Hora']), 1)
        pdf.cell(60, 10, str(row['Resultado']), 1)
        pdf.cell(40, 10, str(row['Tamaño']), 1)
        pdf.cell(40, 10, str(row['Frecuencia']), 1, 1)
    return pdf.output(dest='S').encode('latin-1')

def guardar_log(dato):
    df_nuevo = pd.DataFrame([dato])
    df_nuevo.to_csv('registro_seguridad.csv', mode='a', header=not os.path.isfile('registro_seguridad.csv'), index=False)

def cargar_historial():
    if os.path.isfile('registro_seguridad.csv'): return pd.read_csv('registro_seguridad.csv')
    return pd.DataFrame(columns=["Tamaño", "Frecuencia", "Resultado", "Hora"])

@st.cache_resource
def cargar_modelo(): return joblib.load('centinela_ia.pkt')

modelo = cargar_modelo()
if 'pagina' not in st.session_state: st.session_state.pagina = "inicio"

def ir_a(nueva_pagina):
    st.session_state.pagina = nueva_pagina
    st.rerun()

# --- NAVEGACIÓN PRINCIPAL ---

# PANTALLA: INICIO (DASHBOARD TOTAL)
if st.session_state.pagina == "inicio":
    st.markdown("# 🛡️ Sistema Centinela IA v4.0")
    st.markdown("### Command Center: Intelligence & Cyber-Ops")
    st.divider()
    
    col1, col2, col3 = st.columns(3, gap="large")
    with col1:
        st.image("https://cdn-icons-png.flaticon.com/512/2592/2592223.png", width=120)
        st.subheader("🔍 Escáner Pro")
        st.write("Análisis profundo de archivos y reputación global de URLs vía VirusTotal.")
        if st.button("ABRIR TERMINAL DE ESCANEO"): ir_a("simulador")
    with col2:
        st.image("https://cdn-icons-png.flaticon.com/512/1000/1000966.png", width=120)
        st.subheader("📊 Inteligencia")
        st.write("Mapa de calor de ataques, logs históricos y generación de reportes PDF.")
        if st.button("VER BASE DE INTELIGENCIA"): ir_a("mapa")
    with col3:
        st.image("https://cdn-icons-png.flaticon.com/512/4115/4115591.png", width=120)
        st.subheader("🛰️ Radar Live")
        st.write("Monitoreo táctico de recursos con detección de anomalías por IA.")
        if st.button("ACTIVAR RADAR LIVE"): ir_a("radar")

# PANTALLA: ESCÁNER (VIRUSTOTAL REPARADO)
elif st.session_state.pagina == "simulador":
    st.header("🔍 Terminal de Escaneo Profundo")
    if st.button("⬅️ VOLVER AL PANEL"): ir_a("inicio")
    
    # PEGA TU API KEY AQUÍ
    VT_API_KEY = "07682d116d6da48236c2fb81fe8da6aba31c4e98860026a03d0ed1d64ab26053" 
    
    tab_files, tab_url = st.tabs(["📁 ANÁLISIS DE ARCHIVOS", "🌐 ANÁLISIS DE URLS"])
    with tab_files:
        archivo = st.file_uploader("Arrastre archivo sospechoso aquí")
        if archivo:
            sha256 = hashlib.sha256(archivo.getvalue()).hexdigest()
            st.code(f"SHA256: {sha256}")
            res = "AMENAZA" if modelo.predict([[archivo.size/1024, 0.5]])[0] == -1 else "SEGURO"
            st.error("❌ DETECTADO COMO AMENAZA") if res == "AMENAZA" else st.success("🟢 ARCHIVO SEGURO")
            guardar_log({"Tamaño": archivo.size/1024, "Frecuencia": 0.5, "Resultado": res, "Hora": time.strftime("%H:%M:%S")})

    with tab_url:
        u_in = st.text_input("Ingresar URL para análisis multi-antivirus:")
        if st.button("ESCANEAR EN LA NUBE"):
            with st.spinner("Consultando motores globales..."):
                u_id = base64.urlsafe_b64encode(u_in.encode()).decode().strip("=")
                res = requests.get(f"https://www.virustotal.com/api/v3/urls/{u_id}", headers={"x-apikey": VT_API_KEY})
                if res.status_code == 200:
                    st.subheader("📊 Reporte VirusTotal")
                    stats = res.json()['data']['attributes']['last_analysis_stats']
                    c1, c2, c3 = st.columns(3)
                    c1.metric("MALICIOSOS", f"{stats['malicious']} 🚩")
                    c2.metric("SOSPECHOSOS", f"{stats['suspicious']} ⚠️")
                    c3.metric("LIMPIOS", f"{stats['harmless']} ✅")
                else: st.warning("URL no encontrada o nueva.")

# PANTALLA: MAPA (FULL ESPACIO + PDF + LIMPIEZA)
elif st.session_state.pagina == "mapa":
    st.header("📊 Inteligencia de Datos")
    if st.button("⬅️ VOLVER"): ir_a("inicio")
    
    df = cargar_historial()
    if not df.empty:
        col_viz, col_btn = st.columns([4, 1])
        with col_viz:
            fig = px.scatter(df, x="Tamaño", y="Frecuencia", color="Resultado", template="plotly_dark", color_discrete_map={"SEGURO": "#00FF00", "AMENAZA": "#FF0000"})
            st.plotly_chart(fig, use_container_width=True)
        with col_btn:
            st.subheader("Acciones Tácticas")
            if st.button("📥 GENERAR REPORTE PDF"):
                pdf = generar_pdf(df)
                st.download_button("DESCARGAR ARCHIVO PDF", pdf, "reporte.pdf", "application/pdf")
            if st.button("🗑️ LIMPIAR HISTORIAL"):
                if os.path.exists('registro_seguridad.csv'): os.remove('registro_seguridad.csv')
                st.rerun()
        st.dataframe(df.tail(15), use_container_width=True)

# PANTALLA: RADAR (LAS 2 GRÁFICAS + NOTIFICACIONES)
elif st.session_state.pagina == "radar":
    st.header("🛰️ Radar Táctico de Intercepción")
    if st.button("⬅️ VOLVER AL PANEL"): ir_a("inicio")
    
    m_cont = st.empty(); g_cont = st.empty()
    
    if st.button("🔴 INICIAR MONITOREO DE SISTEMA"):
        h_red = pd.DataFrame(columns=['Red']); h_cpu = pd.DataFrame(columns=['CPU'])
        for i in range(30):
            cpu_val = psutil.cpu_percent(); net_val = psutil.net_io_counters().bytes_sent / 1024
            res = "AMENAZA" if modelo.predict([[net_val, cpu_val/100]])[0] == -1 else "SEGURO"
            
            with m_cont.container():
                c1, c2 = st.columns(2)
                c1.metric("TRÁFICO RED (KB/s)", f"{net_val:.1f}")
                c2.metric("USO CPU (%)", cpu_val)
                if res == "AMENAZA":
                    st.toast("🚨 ¡ALERTA DE SEGURIDAD!", icon="🚨")
                    st.error("AMENAZA EN TIEMPO REAL DETECTADA")
                else: st.success("ESTADO DEL SISTEMA: ESTABLE")

            # ACTUALIZACIÓN DE LAS 2 GRÁFICAS
            h_red = pd.concat([h_red, pd.DataFrame({'Red': [net_val]})], ignore_index=True)
            h_cpu = pd.concat([h_cpu, pd.DataFrame({'CPU': [cpu_val]})], ignore_index=True)
            
            with g_cont.container():
                st.write("📈 Flujo de Datos de Red")
                st.line_chart(h_red, color="#0077FF", use_container_width=True)
                st.write("📊 Carga de Procesamiento (CPU)")
                st.line_chart(h_cpu, color="#FF3333", use_container_width=True)
            
            guardar_log({"Tamaño": net_val, "Frecuencia": cpu_val/100, "Resultado": res, "Hora": time.strftime("%H:%M:%S")})
            time.sleep(1)