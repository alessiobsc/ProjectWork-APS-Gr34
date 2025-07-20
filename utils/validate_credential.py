import re
from datetime import datetime

def validate_credential(credential):
    errors = []

    # 1. Numero massimo di esami superati (max 50)
    if len(credential.get("esami_superati", [])) > 50:
        errors.append("Superato il numero massimo di esami consentiti (max 50)")

    # 2. Numero massimo attività facoltative (max 10)
    if len(credential.get("attività_facoltative", [])) > 10:
        errors.append("Superato il numero massimo di attività facoltative consentite (max 10)")

    # 3. Lunghezza massima nome (max 50)
    nome = credential.get("student", {}).get("nome", "")
    if len(nome) > 50:
        errors.append("Nome troppo lungo (max 50 caratteri)")

    # 4. Lunghezza massima cognome (max 50)
    cognome = credential.get("student", {}).get("cognome", "")
    if len(cognome) > 50:
        errors.append("Cognome troppo lungo (max 50 caratteri)")

    # 5. Lunghezza massima attività facoltative (max 100 ciascuna)
    for attività in credential.get("attività_facoltative", []):
        if len(attività) > 100:
            errors.append(f"Attività facoltativa troppo lunga: '{attività}' (max 100 caratteri)")

    # 6. Range voti esami (18–31 inclusi)
    for esame in credential.get("esami_superati", []):
        voto = esame.get("voto")
        try:
            voto_int = int(voto)
            if not (18 <= voto_int <= 31):
                errors.append(f"Voto fuori dal range consentito (18–31): {voto}")
        except ValueError:
            errors.append(f"Voto non numerico: {voto}")

    # 7. Formato date: YYYY-MM-DD
    date_fields = [e.get("data_superamento") for e in credential.get("esami_superati", [])]
    date_fields.append(credential.get("metadata", {}).get("data_rilascio"))
    for d in date_fields:
        if d:
            try:
                datetime.strptime(d, "%Y-%m-%d")
            except ValueError:
                errors.append(f"Data non conforme al formato YYYY-MM-DD: {d}")

    # Risultato della validazione
    if errors:
        raise ValueError("❌ Validazione fallita:\n" + "\n".join(errors))
    else:
        print("✅ Credenziale valida")
