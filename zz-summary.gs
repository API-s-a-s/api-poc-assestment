/**
 * Script de Orquestación y Consolidación para la hoja "Semaforo".
 * Agrupa dinámicamente por la tercera columna (Categoría) de la hoja "Scores",
 * calcula el promedio de la segunda columna y mapea el estado cualitativo de riesgo.
 * * Nombre del archivo recomendado: zz_SemaforoSummary.gs
 */
function generarResumenSemaforo() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const scoresSheet = ss.getSheetByName("Scores");
  
  if (!scoresSheet) {
    throw new Error("La hoja 'Scores' no existe. Asegúrate de ejecutar primero tus estrategias de auditoría.");
  }
  
  // Buscar u obtener la hoja Preguntas generales
  let semaforoSheet = ss.getSheetByName("Preguntas generales");
  if (!semaforoSheet) {
    semaforoSheet = ss.insertSheet("Preguntas generales");
  }
  // IMPORTANTE: NO usamos semaforoSheet.clear() para no borrar otros elementos de la hoja.
  
  // Obtener los datos reales de la hoja de Scores
  const data = scoresSheet.getDataRange().getValues();
  if (data.length === 0) {
    Logger.log("[WARN] La hoja 'Scores' está vacía.");
    return;
  }
  
  // Estructuras para la agrupación y promedios dinámicos
  const agrupacionCategorias = {};
  let sumaGlobalScores = 0;
  let totalGlobalScores = 0;
  
  // Procesar fila por fila (sin encabezado: la fila 1 ya contiene ID-001)
  for (let i = 0; i < data.length; i++) {
    const scoreNum = parseFloat(data[i][1]); // Segunda Columna (B): Puntuación entera del 1 al 3
    const categoria = data[i][2];            // Tercera Columna (C): Texto de la Categoría
    
    if (!categoria) continue; // Ignorar filas que no tengan categoría asignada
    
    const catTrim = categoria.toString().trim();
    
    // Si la categoría no ha sido registrada, la inicializamos dinámicamente
    if (!agrupacionCategorias[catTrim]) {
      agrupacionCategorias[catTrim] = [];
    }
    
    // Acumular valores numéricos para el promedio por categoría y el global
    if (!isNaN(scoreNum)) {
      agrupacionCategorias[catTrim].push(scoreNum);
      sumaGlobalScores += scoreNum;
      totalGlobalScores++;
    }
  }
  
  // Función para mapear el score numérico
  function obtenerEtiquetaResultado(score) {
    if (score >= 1.00 && score <= 1.89) return "🟢Sólido";
    if (score >= 1.90 && score <= 2.39) return "🟡Mejorable";
    if (score >= 2.40 && score <= 3.00) return "🔴Crítico";
    return "N/A";
  }
  
  // Construir la matriz estructurada final (Únicamente 2 columnas de datos)
  const matrizSalida = [];
  
  // Fila 1: Título unificado (Abarcará las 2 columnas)
  matrizSalida.push(["Resumen y score global", ""]);
  
  // Fila 2: Encabezados limpios (Modificado: "Resultado" en vez de "Promedio")
  matrizSalida.push(["Categoría", "Resultado"]);
  
  // Filas de Datos: Una única fila por cada categoría detectada
  for (const cat in agrupacionCategorias) {
    const listaScores = agrupacionCategorias[cat];
    let promedioCat = 0;
    
    if (listaScores.length > 0) {
      const suma = listaScores.reduce((a, b) => a + b, 0);
      promedioCat = parseFloat((suma / listaScores.length).toFixed(2));
    }
    
    // Convertir el promedio flotante a su etiqueta correspondiente
    const etiquetaResultado = obtenerEtiquetaResultado(promedioCat);
    matrizSalida.push([cat, etiquetaResultado]);
  }
  
  // Fila Final: Promedio global de todo el tenant convertido a etiqueta cualitativa
  let scoreGlobalCompleto = 0;
  if (totalGlobalScores > 0) {
    scoreGlobalCompleto = parseFloat((sumaGlobalScores / totalGlobalScores).toFixed(2));
  }
  const etiquetaGlobal = obtenerEtiquetaResultado(scoreGlobalCompleto);
  matrizSalida.push(["Score global de ciberseguridad", etiquetaGlobal]);
  
  // --- PARTE DE RENDERIZADO Y DISEÑO ESTÉTICO EN GOOGLE SHEETS ---
  const filaInicio = 12; // Inicia en la fila 12 según requerimiento
  const colInicio = 2;  // Inicia en la Columna B (B12)
  const totalFilas = matrizSalida.length;
  const totalColumnas = 2;
  
  // Limpiar el rango específico donde va la tabla para no dejar rastros de ejecuciones anteriores más largas
  semaforoSheet.getRange(filaInicio, colInicio, 50, totalColumnas).clear();

  // Escribir la matriz de datos de golpe en el rango correspondiente
  const rangoTabla = semaforoSheet.getRange(filaInicio, colInicio, totalFilas, totalColumnas);
  rangoTabla.setValues(matrizSalida);
  
  // 1. Estilo de Fila de Título Principal (Combinada)
  const rangoTitulo = semaforoSheet.getRange(filaInicio, colInicio, 1, totalColumnas);
  rangoTitulo.merge(); // Combina horizontalmente las 2 columnas de la cabecera superior
  rangoTitulo.setBackground("#1a365d") // Azul oscuro ejecutivo
             .setFontColor("#ffffff")
             .setFontWeight("bold")
             .setFontSize(11)
             .setHorizontalAlignment("center")
             .setVerticalAlignment("middle");
  semaforoSheet.setRowHeight(filaInicio, 36);
  
  // 2. Estilo de Fila de Encabezados
  const filaEncabezados = filaInicio + 1;
  const rangoEncabezados = semaforoSheet.getRange(filaEncabezados, colInicio, 1, totalColumnas);
  rangoEncabezados.setBackground("#2b6cb0") // Azul cobalto corporativo
                  .setFontColor("#ffffff")
                  .setFontWeight("bold")
                  .setFontSize(10)
                  .setHorizontalAlignment("center")
                  .setVerticalAlignment("middle");
  semaforoSheet.setRowHeight(filaEncabezados, 26);
  
  // 3. Estilo Dinámico para las Filas de Categorías
  const totalCategorias = Object.keys(agrupacionCategorias).length;
  const filaDatosInicio = filaEncabezados + 1;
  
  for (let r = 0; r < totalCategorias; r++) {
    const rowNum = filaDatosInicio + r;
    semaforoSheet.setRowHeight(rowNum, 24);
    
    // Zebra Striping: Colores alternos muy tenues para agilizar el análisis visual
    if (r % 2 === 1) {
      semaforoSheet.getRange(rowNum, colInicio, 1, totalColumnas).setBackground("#f7fafc");
    }
    
    // Formato por columnas independientes
    semaforoSheet.getRange(rowNum, colInicio).setFontColor("#2d3748").setHorizontalAlignment("left").setVerticalAlignment("middle");
    
    // Quitamos setNumberFormat("0.00") de la segunda columna ya que ahora insertamos texto plano (Emojis)
    semaforoSheet.getRange(rowNum, colInicio + 1).setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
  }
  
  // 4. Estilo de Fila del Score Global (Última Fila de la Tabla)
  const filaGlobal = filaDatosInicio + totalCategorias;
  semaforoSheet.setRowHeight(filaGlobal, 32);
  
  const rangoGlobal = semaforoSheet.getRange(filaGlobal, colInicio, 1, totalColumnas);
  rangoGlobal.setBackground("#edf2f7") // Fondo gris de consolidación
             .setFontWeight("bold")
             .setVerticalAlignment("middle");
             
  // Formato texto de cierre
  semaforoSheet.getRange(filaGlobal, colInicio).setFontColor("#1a202c").setHorizontalAlignment("left");
  // Formato resultado global destacado (Modificado a texto plano auditable en vez de número float)
  semaforoSheet.getRange(filaGlobal, colInicio + 1).setFontColor("#2b6cb0").setHorizontalAlignment("center");
  
  // 5. Acabado Profesional y Ocultamiento de la Cuadrícula Infinita
  rangoTabla.setBorder(true, true, true, true, true, true, "#cbd5e0", SpreadsheetApp.BorderStyle.SOLID);
  semaforoSheet.setHiddenGridlines(true);
  
  // 6. Configuración de Anchos Óptimos para la Tabla de 2 Columnas
  semaforoSheet.setColumnWidth(colInicio, 280);     // Ancho columna Categoría (Col B)
  semaforoSheet.setColumnWidth(colInicio + 1, 110);  // Ancho columna Resultado (Col C)
  
  Logger.log("[LOG] Cuadro resumen dinámico cualitativo renderizado con éxito en la hoja 'Preguntas generales'.");
}