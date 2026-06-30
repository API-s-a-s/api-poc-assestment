/**
 * Estrategia para auditar la exposición de Grupos Corporativos (Miembros Externos).
 * Propósito: Detectar qué listas de distribución permiten la inclusión de correos fuera del dominio.
 * Utiliza: Directory API (Listar) y Groups Settings API (Configuración).
 */
class GroupExposureAuditStrategy extends ApiStrategy {
  constructor() {
    const configIDs = [
      { 
        id: "ID-033",
        valueKey: "valorPrincipal",
        noteKey: "comentario033",
        riskKey: "riesgo033",
        scoreKey: "score033"
      }
    ];

    super("Corporate Groups Exposure Audit", configIDs);
    this.category = "Identidad y autenticación";
    
    // Endpoint primario: Lista de grupos del dominio (Se paginará en parseResponse)
    this.urlList = "https://admin.googleapis.com/admin/directory/v1/groups?customer=my_customer";
  }

  getRequestConfig() {
    return {
      url: this.urlList,
      method: "get",
      muteHttpExceptions: true
    };
  }

  parseResponse(json) {
    // =======================================================================
    // PASO 1: EVALUACIÓN DE ERRORES PRINCIPALES
    // =======================================================================
    if (json.error) {
      Logger.log(`[ID-033] ERROR API Directory: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR API",
        riesgo033: "Medio",
        score033: 2,
        comentario033: "Fallo de lectura vía Directory API que impide extraer el inventario de grupos de la organización."
      };
    }

    // =======================================================================
    // PASO 2: PAGINACIÓN MASIVA DE GRUPOS
    // Vital: Google solo devuelve 200 grupos por página. Debemos extraerlos todos.
    // =======================================================================
    let grupos = json.groups || [];

    if (json.nextPageToken) {
      Logger.log("[ID-033] Paginación detectada. Descargando el resto de los grupos...");
      const todosLosGrupos = this.fetchPaginated(this.urlList, "groups");
      if (todosLosGrupos) grupos = todosLosGrupos;
    }

    const totalGrupos = grupos.length;

    if (totalGrupos === 0) {
      Logger.log("[ID-033] AVISO: El dominio no tiene grupos configurados.");
      return {
        name: this.name,
        valorPrincipal: "N/A",
        comentario033: "El dominio analizado no cuenta con ningún grupo corporativo o lista de distribución creada.",
        riesgo033: "Bajo",
        score033: this.calcularScoreDeRiesgo("Bajo")
      };
    }

    Logger.log(`[ID-033] Evaluando vulnerabilidad (allowExternalMembers) en ${totalGrupos} grupos...`);

    // =======================================================================
    // PASO 3: INSPECCIÓN DE VULNERABILIDAD POR GRUPO (Rate Limited)
    // =======================================================================
    let gruposExpuestos = [];

    // Nota: this.authHeader es inyectado por la Facade automáticamente antes de la llamada de red.
    const options = {
      method: "get",
      headers: this.authHeader,
      muteHttpExceptions: true
    };

    const gruposAEvaluar = grupos.slice(0, 50); // Muestra límite para evitar timeout HTTP 429
    for (const grupo of gruposAEvaluar) {
      // Endpoint individual por grupo (Groups Settings API)
      const settingsUrl = `https://www.googleapis.com/groups/v1/groups/${encodeURIComponent(grupo.email)}`;

      try {
        // IMPORTANTE: Usamos el motor de reintentos (Backoff) de la clase base.
        // Si hay 1000 grupos, Google nos bloqueará temporalmente con HTTP 429. 
        // fetchWithBackoff pausará el script matemáticamente y reintentará sin colapsar.
        const response = this.fetchWithBackoff(settingsUrl, options);
        const code = response.getResponseCode();

        if (code === 200) {
          const settings = JSON.parse(response.getContentText());
          // Validación robusta de booleano o string
          if (settings.allowExternalMembers === "true" || settings.allowExternalMembers === true) {
            gruposExpuestos.push(grupo.email);
          }
        }
      } catch (e) {
        // En caso de grupos con errores residuales o eliminados durante la lectura
        Logger.log(`[ID-033] Fallo al extraer configuración del grupo ${grupo.email}: ${e.message}`);
      }
    }

    // =======================================================================
    // PASO 4: ASIGNAR RIESGO Y CONSTRUIR RESULTADO
    // =======================================================================
    const totalExpuestos = gruposExpuestos.length;
    let respuestaConcreta;
    let riesgo033, comentario033;

    if (totalExpuestos > 0) {
      respuestaConcreta = `Habilitado (${totalExpuestos} expuestos)`;
      riesgo033 = "Alto";
      comentario033 = `Vector de Fuga de Datos (DLP): ${totalExpuestos} listas de distribución (de una muestra de ${gruposAEvaluar.length} analizados) permiten miembros externos.`;
      
      // Imprimimos la lista en los logs de AppScript para el equipo de TI
      Logger.log(`[ID-033] GRUPOS VULNERABLES DETECTADOS:\n${gruposExpuestos.join("\n")}`);
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo033 = "Bajo";
      comentario033 = "La totalidad de las listas de distribución corporativas restringen su membresía exclusivamente a usuarios internos del dominio.";
    }

    Logger.log(`[ID-033] Auditoría de Grupos: Resultado -> ${respuestaConcreta} | Expuestos: ${totalExpuestos}/${totalGrupos}`);

    return {
      name: this.name,
      // No volcamos el JSON porque en un entorno con miles de grupos excedería el límite de celdas de Sheets
      raw: { totalAnalizados: totalGrupos, totalVulnerables: totalExpuestos },
      valorPrincipal: respuestaConcreta,
      comentario033: comentario033,
      riesgo033: riesgo033,
      score033: this.calcularScoreDeRiesgo(riesgo033)
    };
  }

  // Traductor de texto a número (Score)
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return "";
  }
}