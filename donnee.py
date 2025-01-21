import re
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import webbrowser
import os
import markdown

# Fonction pour analyser le fichier TCPDump
def analyze_file(file_content):
    issues = []
    packet_counts = {
        "DNS NXDomain": 0,
        "Suspicious SYN": 0,
        "Repeated Payload": 0,
        "Total Packets": 0,
        "Errors": 0
    }
    events = []

    # Compter le nombre total de paquets
    all_packets_pattern = re.compile(r"^\d+", re.MULTILINE)
    all_packets = all_packets_pattern.findall(file_content)
    packet_counts["Total Packets"] = len(all_packets)

    # Rechercher les paquets suspects
    dns_frames = list(set(re.findall(r".*NXDomain.*", file_content, re.MULTILINE)))
    syn_frames = list(set(re.findall(r"IP \S+ > \S+\.http: Flags \[S\].*?", file_content)))
    repeated_frames = list(set(re.findall(r".*5858 5858.*", file_content)))
    error_frames = list(set(re.findall(r".*error.*", file_content, re.MULTILINE)))

    # Extraire les informations supplémentaires
    event_pattern = re.compile(r"(\d{2}:\d{2}:\d{2}\.\d{6}) IP (\S+)\.(\d+) > (\S+): Flags \[(\S+)\], seq (\d+), ack (\d+), win (\d+), options \[(.*?)\], length (\d+)")
    events = event_pattern.findall(file_content)

    # Mettre à jour les compteurs de paquets
    packet_counts["DNS NXDomain"] = len(dns_frames)
    packet_counts["Suspicious SYN"] = len(syn_frames)
    packet_counts["Repeated Payload"] = len(repeated_frames)
    packet_counts["Errors"] = len(error_frames)

    # Stocker les détails des trames
    for frame in dns_frames:
        issues.append(["Erreur DNS", "Échec de la résolution DNS", frame])
    for frame in syn_frames:
        issues.append(["Drapeau SYN", "Connexion SYN suspecte", frame])
    for frame in repeated_frames:
        issues.append(["Répétition", "Données de charge utile répétées", frame])
    for frame in error_frames:
        issues.append(["Erreur", "Erreur détectée dans le paquet", frame])

    print(f"Nombre total d'événements extraits : {len(events)}")
    return issues, packet_counts, events

# Fonction pour générer un rapport Excel
def generate_excel(issues):
    path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("Fichiers CSV", "*.csv")])
    if path:
        try:
            df = pd.DataFrame(issues, columns=["Type", "Description", "Trame"])
            df.to_csv(path, index=False, sep=';', encoding='utf-8-sig')
            messagebox.showinfo("Succès", "Résultats enregistrés dans un fichier CSV.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'enregistrer le fichier : {e}")

# Fonction pour générer un rapport HTML
def save_as_HTML(issues):
    markdown_content = "# Résultats de l'analyse TCP\n\n"
    markdown_content += "| Type | Description | Trame |\n"
    markdown_content += "| ---  | ---         | ---   |\n"
    for issue in issues:
        markdown_content += f"| {issue[0]} | {issue[1]} | {issue[2]} |\n"
    html_converted_content = markdown.markdown(markdown_content, extensions=['tables'])

    counts = {"DNS NXDomain": 0, "Suspicious SYN": 0, "Repeated Payload": 0, "Errors": 0}
    for i in issues:
        if i[0] == "Erreur DNS":
            counts["DNS NXDomain"] += 1
        elif i[0] == "Drapeau SYN":
            counts["Suspicious SYN"] += 1
        elif i[0] == "Répétition":
            counts["Repeated Payload"] += 1
        elif i[0] == "Erreur":
            counts["Errors"] += 1
    counts["Total Packets"] = sum(counts.values())

    fig, ax = plt.subplots(figsize=(12, 8))
    ax.bar(counts.keys(), counts.values(), color=['skyblue', 'lightcoral', 'lightgreen', 'lightyellow'])
    ax.set_title("Répartition des paquets")
    ax.set_xlabel("Type de problème")
    ax.set_ylabel("Nombre de paquets")

    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    bar_chart_filename = "bar_chart.png"
    bar_chart_full_path = os.path.join(desktop_path, bar_chart_filename)
    fig.savefig(bar_chart_full_path)
    plt.close(fig)

    final_html_content = f"""
    <html>
    <head>
        <title>Analyse TCP</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #4CAF50; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            h1 {{ color: #4CAF50; }}
        </style>
    </head>
    <body>
        {html_converted_content}
        <h2>Graphique en barres (Répartition des paquets)</h2>
        <img src="{bar_chart_filename}" alt="Graphique en barres" width="600" />
    </body>
    </html>
    """

    path = os.path.join(os.path.expanduser("~"), "Desktop", "tcp_analysis.html")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(final_html_content)
    webbrowser.open('file://' + path)

# Fonction pour générer un rapport HTML pour les événements
def save_events_as_HTML(events):
    markdown_content = "# Informations des événements TCP\n\n"
    markdown_content += "| Date | Source | Port | Destination | Flag | Seq | Ack | Win | Options | Length |\n"
    markdown_content += "| ---  | ------ | ---- | ----------- | ---- | --- | --- | --- | ------- | ------ |\n"
    for event in events:
        markdown_content += f"| {event[0]} | {event[1]} | {event[2]} | {event[3]} | {event[4]} | {event[5]} | {event[6]} | {event[7]} | {event[8]} | {event[9]} |\n"
    html_converted_content = markdown.markdown(markdown_content, extensions=['tables'])

    final_html_content = f"""
    <html>
    <head>
        <title>Informations des événements TCP</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #4CAF50; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            h1 {{ color: #4CAF50; }}
        </style>
    </head>
    <body>
        {html_converted_content}
    </body>
    </html>
    """

    path = os.path.join(os.path.expanduser("~"), "Desktop", "tcp_events.html")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(final_html_content)
    webbrowser.open('file://' + path)

# Fonction pour générer un CSV pour les événements
def generate_events_csv(events):
    path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("Fichiers CSV", "*.csv")])
    if path:
        try:
            df = pd.DataFrame(events, columns=["Date", "Source", "Port", "Destination", "Flag", "Seq", "Ack", "Win", "Options", "Length"])
            df.to_csv(path, index=False, sep=';', encoding='utf-8-sig')
            messagebox.showinfo("Succès", "Informations des événements enregistrées dans un fichier CSV.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'enregistrer le fichier : {e}")

# Fonction pour afficher les critères d'analyse des erreurs
def show_error_criteria():
    criteria_window = tk.Toplevel()
    criteria_window.title("Critères d'analyse des erreurs")
    criteria_text = """
    Critères d'analyse des erreurs :
    - Erreur DNS : Échec de la résolution DNS (contient 'NXDomain')
    - Drapeau SYN : Connexion SYN suspecte (contient 'Flags [S]')
    - Répétition : Données de charge utile répétées (contient '5858 5858')
    - Erreur : Erreur détectée dans le paquet (contient 'error')
    """
    label = tk.Label(criteria_window, text=criteria_text, justify=tk.LEFT, padx=10, pady=10)
    label.pack()

# Fonction pour charger et analyser le fichier
def load_file():
    path = filedialog.askopenfilename()
    if path:
        try:
            with open(path, 'r') as f:
                content = f.read()
                results, packet_counts, events = analyze_file(content)
                display_results(results, packet_counts, events)
        except Exception as e:
            print("Erreur :", e)

# Fonction pour afficher les résultats de l'analyse
def display_results(issues, packet_counts, events):
    results_window = tk.Toplevel()
    results_window.title("Résultats de l'analyse")

    # Tableau des problèmes détectés
    tree = ttk.Treeview(results_window)
    tree["columns"] = ("Type", "Description", "Trame")
    tree.column("#0", width=0, stretch=tk.NO)
    tree.column("Type", anchor=tk.W, width=120)
    tree.column("Description", anchor=tk.W, width=200)
    tree.column("Trame", anchor=tk.W, width=400)
    tree.heading("#0", text="", anchor=tk.W)
    tree.heading("Type", text="Type", anchor=tk.W)
    tree.heading("Description", text="Description", anchor=tk.W)
    tree.heading("Trame", text="Trame suspecte", anchor=tk.W)
    tree.pack(fill=tk.BOTH, expand=True)

    for issue in issues:
        tree.insert("", tk.END, values=issue)

    # Tableau des événements
    event_tree = ttk.Treeview(results_window)
    event_tree["columns"] = ("Date", "Source", "Port", "Destination", "Flag", "Seq", "Ack", "Win", "Options", "Length")
    event_tree.column("#0", width=0, stretch=tk.NO)
    event_tree.column("Date", anchor=tk.W, width=120)
    event_tree.column("Source", anchor=tk.W, width=120)
    event_tree.column("Port", anchor=tk.W, width=50)
    event_tree.column("Destination", anchor=tk.W, width=120)
    event_tree.column("Flag", anchor=tk.W, width=50)
    event_tree.column("Seq", anchor=tk.W, width=100)
    event_tree.column("Ack", anchor=tk.W, width=100)
    event_tree.column("Win", anchor=tk.W, width=50)
    event_tree.column("Options", anchor=tk.W, width=200)
    event_tree.column("Length", anchor=tk.W, width=50)
    event_tree.heading("#0", text="", anchor=tk.W)
    event_tree.heading("Date", text="Date", anchor=tk.W)
    event_tree.heading("Source", text="Source", anchor=tk.W)
    event_tree.heading("Port", text="Port", anchor=tk.W)
    event_tree.heading("Destination", text="Destination", anchor=tk.W)
    event_tree.heading("Flag", text="Flag", anchor=tk.W)
    event_tree.heading("Seq", text="Seq", anchor=tk.W)
    event_tree.heading("Ack", text="Ack", anchor=tk.W)
    event_tree.heading("Win", text="Win", anchor=tk.W)
    event_tree.heading("Options", text="Options", anchor=tk.W)
    event_tree.heading("Length", text="Length", anchor=tk.W)
    event_tree.pack(fill=tk.BOTH, expand=True)

    for event in events:
        event_tree.insert("", tk.END, values=event)

    print(f"Nombre total d'événements affichés : {len(events)}")

    # Boutons en bas de la page
    button_frame = ttk.Frame(results_window)
    button_frame.pack(pady=10)
    save_csv_button = tk.Button(button_frame, text="Enregistrer en CSV", command=lambda: generate_excel(issues))
    save_csv_button.pack(side=tk.LEFT, padx=5)
    save_html_button = tk.Button(button_frame, text="Ouvrir dans le navigateur", command=lambda: save_as_HTML(issues))
    save_html_button.pack(side=tk.LEFT, padx=5)
    save_events_html_button = tk.Button(button_frame, text="Ouvrir les événements dans le navigateur", command=lambda: save_events_as_HTML(events))
    save_events_html_button.pack(side=tk.LEFT, padx=5)
    save_events_csv_button = tk.Button(button_frame, text="Enregistrer les événements en CSV", command=lambda: generate_events_csv(events))
    save_events_csv_button.pack(side=tk.LEFT, padx=5)
    show_criteria_button = tk.Button(button_frame, text="Afficher les critères d'erreur", command=show_error_criteria)
    show_criteria_button.pack(side=tk.LEFT, padx=5)
    show_graph_button = tk.Button(button_frame, text="Afficher le graphe", command=lambda: show_graph(packet_counts))
    show_graph_button.pack(side=tk.LEFT, padx=5)

    # Filtre en bas de la page
    filter_frame = ttk.Frame(results_window)
    filter_frame.pack(fill=tk.X, padx=10, pady=5)
    ttk.Label(filter_frame, text="Filtrer par type de problème :").pack(side=tk.LEFT, padx=5)
    filter_var = tk.StringVar(value="Tous")
    filter_menu = ttk.Combobox(filter_frame, textvariable=filter_var, state="readonly")
    filter_menu['values'] = ["Tous"] + list(set(issue[0] for issue in issues))
    filter_menu.pack(side=tk.LEFT, padx=5)
    filter_menu.bind("<<ComboboxSelected>>", lambda event: filter_issues(event, tree, issues, filter_var))

def filter_issues(event, tree, issues, filter_var):
    selected_type = filter_var.get()
    for row in tree.get_children():
        tree.delete(row)
    for issue in issues:
        if selected_type == "Tous" or issue[0] == selected_type:
            tree.insert("", tk.END, values=issue)

def show_graph(packet_counts):
    graph_window = tk.Toplevel()
    graph_window.title("Graphique")

    fig = plt.Figure(figsize=(14, 8), dpi=100)
    ax = fig.add_subplot(111)
    ax.bar(packet_counts.keys(), packet_counts.values(), color=['purple', 'red', 'blue', 'green', 'yellow'])
    ax.set_title("Répartition des paquets")
    ax.set_xlabel("Type de problème")
    ax.set_ylabel("Nombre de paquets")

    canvas = FigureCanvasTkAgg(fig, master=graph_window)
    canvas.draw()
    canvas.get_tk_widget().pack(pady=10)

# Application principale
root = tk.Tk()
root.title("Analyseur de paquets TCP")
root.geometry("800x600")

frame = ttk.Frame(root, padding="20")
frame.pack(fill=tk.BOTH, expand=True)

label = ttk.Label(frame, text="Analyseur de paquets TCP", font=("Helvetica", 16))
label.pack(pady=10)

btn = ttk.Button(frame, text="Charger un fichier", command=load_file)
btn.pack(pady=10)

root.mainloop()