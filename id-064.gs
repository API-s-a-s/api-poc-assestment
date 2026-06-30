/**
 * Estrategia para auditar la configuración de Google Workspace Sync para Microsoft Outlook (GWSMO).
 * Evalúa si los usuarios pueden sincronizar datos de la cuenta en clientes de escritorio de Outlook.
 */
class WorkspaceSyncForOutlookStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-064
    const configIDs = [
      { 
        id: "ID-064", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario064",
        riskKey: "riesgo064",
        scoreKey: "score064"
      }
    ];

    super("Workspace Sync for Outlook Audit", configIDs);
    this.category = "Email y DNS";
  }

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

    evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.workspace_sync_for_outlook"));

    let isSyncEnabled = false;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos que no está habilitado explícitamente
      isSyncEnabled = false;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.workspace_sync_for_outlook");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-064] Política raíz efectiva encontrada: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-064] valueNode extraído: ${JSON.stringify(valueNode)}`);
        
        if (valueNode.enableWorkspaceSyncForOutlook === true || 
            (valueNode.state && valueNode.state.toUpperCase() === 'ENABLED')) {
          isSyncEnabled = true;
        }
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo064, comentario064;

    if (isSyncEnabled) {
      // Caso 1: GWSMO habilitado (Riesgo Alto por fuga a PST local)
      respuestaConcreta = "Habilitado";
      riesgo064 = "Alto";
      comentario064 = "Google Workspace Sync para Microsoft Outlook (GWSMO) se encuentra habilitado. Los usuarios pueden descargar y sincronizar correos, calendarios y contactos hacia un cliente local, creando archivos de almacenamiento (PST) en sus dispositivos que evaden los controles de DLP y seguridad nativos de la nube.";
    } else {
      // Caso 2: GWSMO deshabilitado (Seguro)
      respuestaConcreta = "Deshabilitado";
      riesgo064 = "Bajo";
      comentario064 = "La sincronización de Google Workspace para Microsoft Outlook se encuentra deshabilitada de forma estricta. Se bloquea la extracción y el almacenamiento local de información corporativa hacia clientes de escritorio heredados.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Workspace Sync for Outlook Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo064}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario064: comentario064,
      riesgo064: riesgo064,
      score064: this.calcularScoreDeRiesgo(riesgo064)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo064: "Medio", score064: 2, comentario064: msg };
  }
}