# Johan Rojas-Orlando Monsalve-701
# Importa las bibliotecas necesarias para la aplicación
import dash  # Dash es el framework principal para crear la aplicación web
from dash import dcc, html, callback_context  # Componentes principales de Dash: dcc (dash core components) y html (componentes HTML)
from dash.dependencies import Input, Output  # Importa Input y Output para crear callbacks que actualizan los gráficos
import plotly.graph_objs as go  # Importa objetos de gráfico de Plotly para crear visualizaciones interactivas
from pymongo import MongoClient  # Importa MongoClient para conectarse a la base de datos MongoDB
import os  # Importa os para acceder a variables de entorno
import webbrowser  # Importa webbrowser para abrir automáticamente la aplicación en el navegador
from collections import Counter  # Importa Counter de collections para contar elementos
import matplotlib.pyplot as plt  # Importa matplotlib.pyplot para crear gráficos

# Función para conectar a la base de datos MongoDB
def conectar_base_datos():
    # Define la configuración de conexión a la base de datos utilizando variables de entorno
    settings = {
        'host': os.environ.get('MONGO_HOST'),
        'database_id': os.environ.get('MONGO_DATABASE', 'boxeo'),
        'collection_id': os.environ.get('MONGO_COLLECTION', 'lucha')
    }
    # Asigna las configuraciones a variables locales
    HOST = settings['host']
    DATABASE_ID = settings['database_id']
    COLLECTION_ID = settings['collection_id']
    # Verifica que la variable de entorno con la cadena de conexión esté configurada
    if not HOST:
        raise ValueError(
            "No se encontró la variable de entorno MONGO_HOST. "
            "Configúrala con tu cadena de conexión de MongoDB antes de ejecutar la aplicación."
        )
    # Conéctate al servidor de MongoDB
    client = MongoClient(HOST)
    # Accede a la base de datos y la colección específica
    db = client[DATABASE_ID]
    collection = db[COLLECTION_ID]
    return collection  # Devuelve la colección para su uso posterior

# Función para obtener datos para el gráfico de barras
def obtener_datos_barras():
    collection = conectar_base_datos()  # Conéctate a la base de datos
    # Encuentra todos los documentos en la colección, seleccionando solo el campo 'software'
    items = list(collection.find({}, {"software": 1}))
    cve_count = {}  # Diccionario para contar la cantidad de apariciones de cada CVE
    for item in items:
        for software in item.get('software', []):
            for cve in software.get('cves', []):
                cve_id = cve['CVE']
                cve_count[cve_id] = cve_count.get(cve_id, 0) + 1  # Incrementa el conteo para cada CVE
    # Ordena los CVE por su frecuencia y selecciona los 15 más comunes
    sorted_cves = sorted(cve_count.items(), key=lambda x: x[1], reverse=True)[:15]
    top_cve = [cve[0] for cve in sorted_cves]  # Lista de los top 15 CVE
    counts = [cve[1] for cve in sorted_cves]  # Lista de las frecuencias correspondientes
    return top_cve, counts  # Devuelve los datos para el gráfico de barras

# Función para obtener datos para el gráfico de dispersión
def obtener_datos_dispersion():
    collection = conectar_base_datos()  # Conéctate a la base de datos
    # Encuentra todos los documentos en la colección, seleccionando solo el campo 'software'
    items = list(collection.find({}, {"software": 1}))
    software_vulnerability_count = {}  # Diccionario para contar las vulnerabilidades por software
    for item in items:
        for software in item.get('software', []):
            software_name = software['nombre']
            vulnerability_count = len(software.get('cves', []))
            software_vulnerability_count[software_name] = vulnerability_count
    # Ordena los software por el número de vulnerabilidades y selecciona los 15 con más vulnerabilidades
    sorted_software_vulnerability_count = sorted(software_vulnerability_count.items(), key=lambda x: x[1], reverse=True)[:15]
    top_softwares = [item[0] for item in sorted_software_vulnerability_count]  # Lista de los top 15 software
    vulnerabilities = [item[1] for item in sorted_software_vulnerability_count]  # Lista de las vulnerabilidades correspondientes
    return top_softwares, vulnerabilities  # Devuelve los datos para el gráfico de dispersión

# Función para obtener datos para el gráfico de barras de Windows
def obtener_datos_barras_windows():
    collection = conectar_base_datos()  # Conéctate a la base de datos
    # Encuentra todos los documentos en la colección, seleccionando solo el campo 'software'
    items = list(collection.find({}, {"software": 1}))
    software_cve_count = {}  # Diccionario para contar los CVE por software en Windows
    for item in items:
        for software in item.get('software', []):
            for cve in software.get('cves', []):
                os_name = cve.get('Sistema_Operativo_Afectado')
                if os_name == 'Windows':
                    software_name = software['nombre']
                    software_cve_count[software_name] = software_cve_count.get(software_name, 0) + 1  # Incrementa el conteo para cada CVE en Windows
    # Ordena los software por el número de CVE en Windows y selecciona los 15 con más CVE
    sorted_software_cve_count = sorted(software_cve_count.items(), key=lambda x: x[1], reverse=True)[:15]
    top_windows_softwares = [item[0] for item in sorted_software_cve_count]  # Lista de los top 15 software en Windows
    windows_vulnerabilities = [item[1] for item in sorted_software_cve_count]  # Lista de las vulnerabilidades correspondientes
    return top_windows_softwares, windows_vulnerabilities  # Devuelve los datos para el gráfico de barras en Windows

# Función para obtener datos para el gráfico de barras de vulnerabilidades por host
def obtener_datos_barras_vulnerabilidades_por_host():
    collection = conectar_base_datos()  # Conéctate a la base de datos
    host_vulnerabilities = {}  # Diccionario para contar las vulnerabilidades por host
    for doc in collection.find():
        host = doc['nombre_equipo']
        software_list = doc['software']
        # Suma las vulnerabilidades de todos los software en cada host
        total_vulnerabilities = sum(len(software['cves']) for software in software_list)
        host_vulnerabilities[host] = total_vulnerabilities  # Asigna el total de vulnerabilidades al host
    hosts = list(host_vulnerabilities.keys())  # Lista de los nombres de los hosts
    vulnerabilities = list(host_vulnerabilities.values())  # Lista de las vulnerabilidades correspondientes
    return hosts, vulnerabilities  # Devuelve los datos para el gráfico de barras por host

# Función para generar gráfica de los 10 CVE más críticos
def generar_grafica_top_10_cves(resultados_consulta):
    cve_counter = Counter()  # Inicializa un contador para los CVE
    for resultado in resultados_consulta:
        software = resultado.get('software', [])
        for item in software:
            cves = item.get('cves', [])
            for cve in cves:
                cve_counter[cve['CVE']] += 1  # Incrementa el conteo para cada CVE
    top_10_cves = dict(cve_counter.most_common(10))  # Obtiene los 10 CVE más comunes

    # Crea una figura de Plotly con los datos de los 10 CVE más críticos
    fig = go.Figure(data=[go.Bar(
        x=list(top_10_cves.values()),
        y=list(top_10_cves.keys()),
        orientation='h',
        marker=dict(color='skyblue'),
        text=list(top_10_cves.values()),
        textposition='auto'
    )])

    # Actualiza el diseño del gráfico
    fig.update_layout(
        title='Top 10 CVE más Críticos',
        xaxis=dict(title='Cantidad de Ocurrencias'),
        yaxis=dict(title='CVE'),
        plot_bgcolor=colors['background'],
        paper_bgcolor=colors['background'],
        font=dict(color=colors['text']),
        margin=dict(l=40, r=40, t=60, b=40),
        bargap=0.15,
        bargroupgap=0.1
    )

    return fig  # Devuelve la figura del gráfico

# Función para generar gráfica de la suma total de CVEs
def generar_grafica_suma_total_cves(resultados_consulta):
    cve_counter = Counter()  # Inicializa un contador para los CVE
    for resultado in resultados_consulta:
        software = resultado.get('software', [])
        for item in software:
            cves = item.get('cves', [])
            for cve in cves:
                cve_counter[cve['CVE']] += 1  # Incrementa el conteo para cada CVE
    total_cves = sum(cve_counter.values())  # Calcula la suma total de CVE

    # Crea una figura de Plotly con la suma total de CVE
    fig = go.Figure(go.Bar(
        x=["Total de CVEs"],
        y=[total_cves],
        marker=dict(color='#1f77b4')
    ))

    # Actualiza el diseño del gráfico
    fig.update_layout(
        title='Suma Total de CVE en la Base de Datos',
        xaxis=dict(title='CVE'),
        yaxis=dict(title='Suma Total'),
        plot_bgcolor=colors['background'],
        paper_bgcolor=colors['background'],
        font=dict(color=colors['text']),
        margin=dict(l=40, r=40, t=60, b=40),
        bargap=0.15,
        bargroupgap=0.1
    )

    return fig  # Devuelve la figura del gráfico

# Crear la aplicación Dash
app = dash.Dash(__name__)  # Inicializa la aplicación Dash

# Estilos y colores personalizados
colors = {
    'background': '#f8f9fa',  # Color de fondo
    'text': '#343a40',  # Color del texto
    'accent': '#007bff'  # Color de acento
}

# Estilos CSS
external_stylesheets = ['https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css']  # Hoja de estilos CSS externa

# Diseño del dashboard
app.layout = html.Div(style={'backgroundColor': colors['background'], 'fontFamily': 'Arial, sans-serif', 'padding': '30px'}, children=[
    html.Div(className='container', children=[
        html.H1(children='Dashboard de Análisis de Vulnerabilidades', style={'textAlign': 'center', 'marginBottom': '50px', 'color': colors['text'], 'fontSize': '3em'}),
        dcc.Tabs(id='tabs', value='tab-1', children=[
            dcc.Tab(label='Top 15 CVE más Comunes', value='tab-1'),
            dcc.Tab(label='Top 15 Softwares Más Vulnerables', value='tab-2'),
            dcc.Tab(label='Top 15 Software con más CVEs en Windows', value='tab-3'),
            dcc.Tab(label='Número de vulnerabilidades CVE por host', value='tab-4'),
            dcc.Tab(label='Top 10 CVE más Críticos', value='tab-5'),
            dcc.Tab(label='Suma Total de CVEs', value='tab-6')
        ]),
        html.Div(id='tabs-content')  # Contenedor para el contenido de cada pestaña
    ])
])

# Callback para actualizar el contenido basado en la pestaña seleccionada
@app.callback(
    Output('tabs-content', 'children'),
    [Input('tabs', 'value')]
)
def render_content(tab):
    if tab == 'tab-1':
        return html.Div([
            html.H2(children='Top 15 CVE más Comunes', style={'textAlign': 'center', 'marginBottom': '30px', 'color': colors['text'], 'fontSize': '2em'}),
            dcc.Graph(
                id='graph-1',
                figure={
                    'data': [
                        go.Bar(
                            x=obtener_datos_barras()[1],
                            y=obtener_datos_barras()[0],
                            orientation='h',
                            marker=dict(color=colors['accent'], line=dict(color='#000000', width=1))
                        )
                    ],
                    'layout': go.Layout(
                        xaxis={'title': 'Cantidad de Apariciones', 'titlefont': dict(color=colors['text'], size=14)},
                        yaxis={'title': 'CVE', 'titlefont': dict(color=colors['text'], size=14)},
                        margin={'l': 40, 'b': 40, 't': 10, 'r': 10},
                        hovermode='closest',
                        plot_bgcolor=colors['background'],
                        paper_bgcolor=colors['background'],
                        font=dict(color=colors['text'])
                    )
                }
            )
        ])
    elif tab == 'tab-2':
        return html.Div([
            html.H2(children='Top 15 Softwares Más Vulnerables', style={'textAlign': 'center', 'marginBottom': '30px', 'color': colors['text'], 'fontSize': '2em'}),
            dcc.Graph(
                id='graph-2',
                figure={
                    'data': [
                        go.Scatter(
                            x=obtener_datos_dispersion()[0],
                            y=obtener_datos_dispersion()[1],
                            mode='markers',
                            marker=dict(color=colors['accent'], size=12, line=dict(color='#000000', width=1))
                        )
                    ],
                    'layout': go.Layout(
                        xaxis={'title': 'Software', 'titlefont': dict(color=colors['text'], size=14)},
                        yaxis={'title': 'Número de Vulnerabilidades', 'titlefont': dict(color=colors['text'], size=14)},
                        margin={'l': 40, 'b': 40, 't': 10, 'r': 10},
                        hovermode='closest',
                        plot_bgcolor=colors['background'],
                        paper_bgcolor=colors['background'],
                        font=dict(color=colors['text'])
                    )
                }
            )
        ])
    elif tab == 'tab-3':
        return html.Div([
            html.H2(children='Top 15 Software con más CVEs en Windows', style={'textAlign': 'center', 'marginBottom': '30px', 'color': colors['text'], 'fontSize': '2em'}),
            dcc.Graph(
                id='graph-3',
                figure={
                    'data': [
                        go.Bar(
                            x=obtener_datos_barras_windows()[1],
                            y=obtener_datos_barras_windows()[0],
                            orientation='h',
                            marker=dict(color=colors['accent'], line=dict(color='#000000', width=1))
                        )
                    ],
                    'layout': go.Layout(
                        xaxis={'title': 'Cantidad de CVEs', 'titlefont': dict(color=colors['text'], size=14)},
                        yaxis={'title': 'Software', 'titlefont': dict(color=colors['text'], size=14)},
                        margin={'l': 40, 'b': 40, 't': 10, 'r': 10},
                        hovermode='closest',
                        plot_bgcolor=colors['background'],
                        paper_bgcolor=colors['background'],
                        font=dict(color=colors['text'])
                    )
                }
            )
        ])
    elif tab == 'tab-4':
        return html.Div([
            html.H2(children='Número de vulnerabilidades CVE por host', style={'textAlign': 'center', 'marginBottom': '30px', 'color': colors['text'], 'fontSize': '2em'}),
            dcc.Graph(
                id='graph-4',
                figure={
                    'data': [
                        go.Bar(
                            x=obtener_datos_barras_vulnerabilidades_por_host()[0],
                            y=obtener_datos_barras_vulnerabilidades_por_host()[1],
                            marker=dict(color=colors['accent'], line=dict(color='#000000', width=1))
                        )
                    ],
                    'layout': go.Layout(
                        xaxis={'title': 'Host', 'titlefont': dict(color=colors['text'], size=14)},
                        yaxis={'title': 'Número de Vulnerabilidades', 'titlefont': dict(color=colors['text'], size=14)},
                        margin={'l': 40, 'b': 40, 't': 10, 'r': 10},
                        hovermode='closest',
                        plot_bgcolor=colors['background'],
                        paper_bgcolor=colors['background'],
                        font=dict(color=colors['text'])
                    )
                }
            )
        ])
    elif tab == 'tab-5':
        resultados_consulta = conectar_base_datos()  # Ejemplo de conexión a la base de datos
        resultados_consulta = list(resultados_consulta.find())  # Obtener los datos de la base de datos
        return html.Div([
            html.H2(children='Top 10 CVE más Críticos', style={'textAlign': 'center', 'marginBottom': '30px', 'color': colors['text'], 'fontSize': '2em'}),
            dcc.Graph(
                id='graph-5',
                figure=generar_grafica_top_10_cves(resultados_consulta)
            )
        ])
    elif tab == 'tab-6':
        resultados_consulta = conectar_base_datos()  # Ejemplo de conexión a la base de datos
        resultados_consulta = list(resultados_consulta.find())  # Obtener los datos de la base de datos
        return html.Div([
            html.H2(children='Suma Total de CVEs', style={'textAlign': 'center', 'marginBottom': '30px', 'color': colors['text'], 'fontSize': '2em'}),
            dcc.Graph(
                id='graph-6',
                figure=generar_grafica_suma_total_cves(resultados_consulta)
            )
        ])

if __name__ == '__main__':
    webbrowser.open_new('http://127.0.0.1:8050/')  # Abre la aplicación en el navegador
    app.run_server(debug=True, port=8050, use_reloader=False, dev_tools_ui=False, dev_tools_props_check=False)  # Inicia el servidor de la aplicación
