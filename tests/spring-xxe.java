import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

class T {
    DocumentBuilder badDbf() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        // ruleid: spring-xxe-documentbuilderfactory-default
        return f.newDocumentBuilder();
    }

    DocumentBuilder okDbf() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: spring-xxe-documentbuilderfactory-default
        return f.newDocumentBuilder();
    }

    SAXParser badSax() throws Exception {
        SAXParserFactory f = SAXParserFactory.newInstance();
        // ruleid: spring-xxe-saxparserfactory-default
        return f.newSAXParser();
    }

    SAXParser okSax() throws Exception {
        SAXParserFactory f = SAXParserFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: spring-xxe-saxparserfactory-default
        return f.newSAXParser();
    }
}
