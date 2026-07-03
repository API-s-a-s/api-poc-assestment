/**
 * Estrategia para auditar las opciones de uso compartido externo para calendarios principales.
 * Evalúa el parámetro max_allowed_external_sharing.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/calendar.primary_calendar_max_allowed_external_sharing
 */
class CalendarPrimaryExternalSharingStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-117", 
        valueKey: "valorPrincipal",
        noteKey: "comentario117",
        riskKey: "riesgo117",
        scoreKey: "score117"
      }
    ];

    super("Calendar Primary External Sharing Audit", configIDs);
    this.category = "Servicios adicionales";
    this.customerId = customerId;
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

    // Filtramos las políticas pertenecientes al sub-entorno de Calendar (uso compartido externo)
    const targetPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("calendar.primary_calendar_max_allowed_external_sharing"));
    Logger.log(`[ID-117] Se encontraron ${targetPolicies.length} políticas en memoria para este filtro.`);
    if (targetPolicies.length > 0) {
      Logger.log(`[ID-117] Detalles de las políticas encontradas: ` + JSON.stringify(targetPolicies.map(p => ({ type: p.type, name: p.name, sortOrder: p.policyQuery?.sortOrder, hasGroup: !!p.policyQuery?.group, orgUnit: p.policyQuery?.orgUnit }))));
    } else {
      Logger.log(`[ID-117] [WARNING] La API masiva no trajo configuraciones para esta política. Esto puede explicar el retorno NULL o valores por defecto.`);
    }
    
    let extractedValue = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      // Resolvemos los conflictos utilizando el reductor por defecto (Max)
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "calendar.primary_calendar_max_allowed_external_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // Verificación resiliente soportando variantes de nomenclatura
        if (valueNode.max_allowed_external_sharing !== undefined) {
            extractedValue = valueNode.max_allowed_external_sharing;
        } else if (valueNode.maxAllowedExternalSharing !== undefined) {
            extractedValue = valueNode.maxAllowedExternalSharing;
        }
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluamos el enum de max_allowed_external_sharing
    // EXTERNAL_FREE_BUSY_ONLY, EXTERNAL_ALL_INFO_READ_ONLY, EXTERNAL_ALL_INFO_READ_WRITE, EXTERNAL_ALL_INFO_READ_WRITE_MANAGE
    if (extractedValue === "EXTERNAL_FREE_BUSY_ONLY") {
      respuestaConcreta = "Sólo libre/ocupado";
      riesgo = "Bajo";
      comentario = "La configuración limita el uso compartido externo de los calendarios principales únicamente a la disponibilidad de tiempo libre u ocupado. No se exponen detalles de los eventos ni asistentes.";
    } else if (extractedValue === "EXTERNAL_ALL_INFO_READ_ONLY") {
      respuestaConcreta = "Sólo lectura de toda la info";
      riesgo = "Medio";
      comentario = "Se permite a usuarios externos leer toda la información de los calendarios principales. Esto expone descripciones de reuniones, participantes, ubicaciones y temas sensibles.";
    } else if (extractedValue === "EXTERNAL_ALL_INFO_READ_WRITE") {
      respuestaConcreta = "Lectura y escritura de toda la info";
      riesgo = "Alto";
      comentario = "Se permite a usuarios externos ver y modificar eventos en los calendarios principales de los usuarios, lo que incrementa sustancialmente el riesgo de alteración o spam.";
    } else if (extractedValue === "EXTERNAL_ALL_INFO_READ_WRITE_MANAGE") {
      respuestaConcreta = "Administración, lectura y escritura de toda la info";
      riesgo = "Alto";
      comentario = "Se otorga permiso total de administración y delegación a usuarios externos sobre los calendarios principales. Esto expone la agenda corporativa a total manipulación externa.";
    } else {
      respuestaConcreta = "Revisión manual";
      riesgo = "Medio";
      comentario = "La configuración no está explícitamente definida por la política, por lo que hereda el comportamiento predeterminado del sistema o requiere revisión manual en la consola.";
    }

    Logger.log(`[LOG] Calendar Primary External Sharing Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedValue}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario117: comentario,
      riesgo117: riesgo,
      score117: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-117] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo117: "Medio", score117: 2, comentario117: msg };
  }
}
