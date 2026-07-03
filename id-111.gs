/**
 * Estrategia para auditar si se permite Google Drive para escritorio solo en dispositivos autorizados.
 * Evalúa el parámetro restrict_to_authorized_devices.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.drive_for_desktop
 */
class DriveForDesktopAuthorizedDevicesStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-111", 
        valueKey: "valorPrincipal",
        noteKey: "comentario111",
        riskKey: "riesgo111",
        scoreKey: "score111"
      }
    ];

    super("Drive for Desktop Authorized Devices Audit", configIDs);
    this.category = "Drive";
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

    // Filtramos las políticas pertenecientes al sub-entorno de Drive para escritorio
    const targetPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("drive_and_docs.drive_for_desktop"));
    Logger.log(`[ID-111] Se encontraron ${targetPolicies.length} políticas en memoria para este filtro.`);
    if (targetPolicies.length > 0) {
      Logger.log(`[ID-111] Detalles de las políticas encontradas: ` + JSON.stringify(targetPolicies.map(p => ({ type: p.type, name: p.name, sortOrder: p.policyQuery?.sortOrder, hasGroup: !!p.policyQuery?.group, orgUnit: p.policyQuery?.orgUnit }))));
    } else {
      Logger.log(`[ID-111] [WARNING] La API masiva no trajo configuraciones para esta política. Esto puede explicar el retorno NULL o valores por defecto.`);
    }
    
    let extractedValue = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      // Resolvemos los conflictos utilizando el reductor por defecto (Max) para directivas SYSTEM
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "drive_and_docs.drive_for_desktop");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // Verificación resiliente soportando variantes de nomenclatura de variables (snake_case y camelCase)
        if (valueNode.restrict_to_authorized_devices !== undefined) {
            extractedValue = valueNode.restrict_to_authorized_devices;
        } else if (valueNode.restrictToAuthorizedDevices !== undefined) {
            extractedValue = valueNode.restrictToAuthorizedDevices;
        }
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // =======================================================================
    // LÓGICA DE NEGOCIO Y MATRICES DE RIESGO DE SEGURIDAD (ID-111)
    // =======================================================================
    if (extractedValue === true) {
      respuestaConcreta = "Habilitado";
      riesgo = "Bajo"; // Postura segura: Solo hardware verificado puede sincronizar datos
      comentario = "La restricción a dispositivos autorizados está habilitada. El cliente de escritorio solo puede ejecutarse en hardware corporativo certificado y validado.";
    } else if (extractedValue === false) {
      respuestaConcreta = "Deshabilitado";
      riesgo = "Alto"; // Postura vulnerable: Cualquier equipo personal o ajeno puede descargar data masiva
      comentario = "La restricción a dispositivos autorizados está inhabilitada. Cualquier dispositivo puede sincronizar archivos de Drive localmente, aumentando el riesgo de fuga de información.";
    } else {
      respuestaConcreta = "Revisión manual";
      riesgo = "Medio";
      comentario = "La configuración no está explícitamente definida por la política, por lo que hereda el comportamiento predeterminado del sistema.";
    }

    Logger.log(`[LOG] Drive for Desktop Authorized Devices Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo}`);

    // Retorno consolidado mapeado con la matriz del Sheets
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario111: comentario,
      riesgo111: riesgo,
      score111: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-111] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo111: "Medio", score111: 2, comentario111: msg };
  }
}