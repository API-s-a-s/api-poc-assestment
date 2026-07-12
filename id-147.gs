/**
 * Estrategia para auditar si se permite añadir cuentas corporativas vía IMAP en iOS.
 * ID-147: Permitir añadir "Cuenta de Google" a iOS (IMAP).
 * Utiliza Cloud Identity Policy API (evaluada en memoria) para leer la configuración 
 * de settings/gmail.imap_access en la OU raíz.
 */
class AppleAppsImapStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-147", 
        valueKey: "valorPrincipal",
        noteKey: "comentario147",
        riskKey: "riesgo147",
        scoreKey: "score147"
      }
    ];
    super("Apple Apps IMAP Access Audit (ID-147)", configIDs);
    this.customerId = customerId;
    this.category = "Gestión de dispositivos"; // Categoría solicitada
  }

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
    if (!policies) {
      return this._buildErrorResponse("Falta el contexto global (políticas no encontradas en memoria).");
    }

    Logger.log("========== INICIO DIAGNÓSTICO ID-147 (APPLE APPS IMAP) ==========");

    let enableImapAccess = false;
    let policyFound = false;

    try {
      Logger.log(`[ID-147 DEBUG] Total de políticas en globalContext: ${policies.length}`);
      
      // Utilizamos el Reducer para obtener la política efectiva en la raíz para este setting
      const imapPolicy = PolicyReducerFactory.getEffectiveRootPolicy(policies, "settings/gmail.imap_access");
      
      if (imapPolicy) {
        Logger.log(`[ID-147 DEBUG] Objeto completo devuelto por el Reducer: ${JSON.stringify(imapPolicy)}`);
      }
      
      if (imapPolicy && imapPolicy.setting) {
        policyFound = true;
        
        // Determinar de dónde sacar el valor: de .setting o de .setting.value
        let valueNode = imapPolicy.setting.value || imapPolicy.setting;
        
        enableImapAccess = valueNode.enableImapAccess === true;
        
        Logger.log(`[ID-147] Política encontrada. enableImapAccess: ${enableImapAccess}`);
        Logger.log(`[ID-147 RAW LOG] Nodo de valor extraído: ${JSON.stringify(valueNode)}`);
      } else {
        Logger.log("[ID-147] No se encontró política explícita para settings/gmail.imap_access en la raíz.");
      }
    } catch (e) {
      Logger.log(`[ID-147] Excepción capturada al evaluar políticas: ${e.message}`);
      return this._buildErrorResponse(`Error al procesar la política IMAP: ${e.message}`);
    }

    Logger.log("========== FIN DIAGNÓSTICO ID-147 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo147 = "Bajo";
    let comentario147 = "";
    
    // Si no se encuentra la política explícita, los tenants modernos suelen tenerlo habilitado por defecto 
    // a menos que se fuerce el cierre, pero nos apegaremos al valor extraído de la API.
    let valorPrincipal = enableImapAccess ? "Habilitado" : "Deshabilitado";

    if (enableImapAccess) {
      riesgo147 = "Alto";
      comentario147 = "ALERTA: El acceso a través del protocolo IMAP está habilitado. Esto permite que los usuarios configuren buzones corporativos en las aplicaciones nativas de Apple (Mail de iOS/macOS) mediante un protocolo legacy, lo cual genera un alto riesgo de eludir controles modernos de inicio de sesión (MFA/Context-Aware) y rompe la capacidad del MDM corporativo para gestionar esos datos.";
    } else {
      riesgo147 = "Bajo";
      comentario147 = "Excelente postura de seguridad. El acceso IMAP está deshabilitado. Esto obliga a los usuarios de iOS/iPadOS a utilizar aplicaciones modernas (como la app oficial de Gmail) que soportan autenticación robusta y pueden ser puestas en contenedores administrados (MDM).";
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario147: comentario147,
      riesgo147: riesgo147,
      score147: this.calcularScoreDeRiesgo(riesgo147)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-147] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo147: "Medio",
      score147: 2,
      comentario147: msg
    };
  }
}